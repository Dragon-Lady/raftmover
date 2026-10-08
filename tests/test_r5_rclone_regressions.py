"""The supplied r5 real-rclone cases, with fixed-outcome assertions."""
import json
import shutil

import pytest

from raftmover import cli
import raftmover.transport as transport
from test_security import add, pair, rows


@pytest.fixture(autouse=True)
def local_rclone_config(tmp_path, monkeypatch):
    if shutil.which("rclone") is None:
        pytest.skip("rclone unavailable")
    config = tmp_path / "rclone.conf"
    config.write_text("")
    config.chmod(0o600)
    monkeypatch.setenv("RCLONE_CONFIG", str(config))


def rpair(tmp_path):
    a, b, paths, _ = pair(tmp_path)
    store = tmp_path / "store"
    store.mkdir(mode=0o700)
    for engine in (a, b):
        engine.transport = transport.Rclone(":local:" + str(store))
    return a, b, paths, store


def test_R0_rclone_roundtrip_ack_and_prune(tmp_path):
    a, b, paths, store = rpair(tmp_path)
    a.cfg["keep_last_n"] = 1
    with a.locked():
        assert a.send()[0]["status"] == "sent"
    with b.locked():
        b.pickup()
        assert b.adopt("chat-state", keep_both=True)["status"] == "adopted"
    add(paths[1], "receiver new chat")
    with b.locked():
        assert b.send()[0]["status"] == "sent"
    with a.locked():
        assert a.pickup()[0]["status"] == "adopted"
    add(paths[0], "sender continuation")
    with a.locked():
        assert a.send()[0]["status"] == "sent"
    with b.locked():
        assert b.pickup()[0]["status"] == "adopted"
    with a.locked():
        a.pickup()
    assert rows(paths[0]) == rows(paths[1]) == [
        "base", "receiver new chat", "sender continuation"]
    receipts = [json.loads(path.read_text())
                for path in (a.root / "receipts").glob("*.json")]
    assert any(item["status"] == "retired" for item in receipts)


def test_R1_interrupted_manifest_upload_cleans_unpublished_final(tmp_path, monkeypatch):
    a, b, _, store = rpair(tmp_path)
    real = transport._command

    def interrupt(argv, timeout=300):
        if argv[1] == "copyto" and argv[-1].endswith("/manifest.json"):
            raise cli.Terminated
        return real(argv, timeout)

    with monkeypatch.context() as patch:
        patch.setattr(transport, "_command", interrupt)
        with a.locked():
            with pytest.raises(cli.Terminated):
                a.send()
    assert list((store / "incoming").iterdir()) == []
    with b.locked():
        assert b.pickup() == []
    assert cli._exit_code([]) == 0


def test_R2_first_bare_move_creates_incoming_and_sends(tmp_path, monkeypatch, capsys):
    a, _, _, store = rpair(tmp_path)
    monkeypatch.setattr(cli, "load", lambda _: a.cfg)
    monkeypatch.setattr(cli, "Engine", lambda *args, **kwargs: a)
    assert cli.main([]) == 0
    assert "sent" in capsys.readouterr().out
    assert (store / "incoming").is_dir()
    assert a._state("chat-state")["status"] == "sent"


def test_listing_failure_does_not_block_independent_send(tmp_path, monkeypatch):
    a, _, _, store = rpair(tmp_path)
    real = a.transport.packet_ids
    monkeypatch.setattr(a.transport, "packet_ids",
                        lambda: (_ for _ in ()).throw(transport.TransferError("transport-failed")))
    with a.locked():
        pickup = a.pickup()
        send = a.send()
    assert pickup[0]["reason"] == "transport-failed"
    assert send[0]["status"] == "sent"
    monkeypatch.setattr(a.transport, "packet_ids", real)


def test_sftp_requires_verified_host_key(monkeypatch):
    def config(argv, timeout=300):
        if argv[1:3] == ["config", "dump"]:
            return b'{"peer":{"type":"sftp","host":"example.invalid"}}'
        if argv[1:3] == ["config", "providers"]:
            return b'[{"Prefix":"sftp","Overview":{"Virtual":false}}]'
        pytest.fail("network command must not run")

    monkeypatch.setattr(transport, "_command", config)
    with pytest.raises(transport.TransferError, match="sftp-host-key-unverified"):
        transport.Rclone("peer:rafts").packet_ids()


def test_missing_manifest_is_held_for_review(tmp_path):
    a, _, _, store = rpair(tmp_path)
    packet_id = "a" * 32
    packet = store / "incoming" / packet_id
    packet.mkdir(parents=True, mode=0o700)
    (packet / "snapshot.sqlite").write_bytes(b"partial")
    assert a.transport.packet_ids() == []
    with a.locked():
        outcome = a.pickup()
    assert outcome == [{"raft": "packet", "status": "held",
                        "reason": "incomplete-packet"}]
    assert cli._exit_code(outcome) == 3
    destination = tmp_path / "fetch"
    destination.mkdir()
    with pytest.raises(transport.TransferError, match="incomplete-packet"):
        a.transport.fetch_manifest(packet_id, destination)
    assert cli._exit_code([{"raft": "packet", "status": "held",
                            "reason": "incomplete-packet"}]) == 3
