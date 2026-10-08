"""Regression cases for supervised handoff and transport preflight."""
import json
import os
import time

import pytest
import raftward

from raftmover import cli
from raftmover.engine import MoveError, ward_api
from raftmover.transport import Rclone, TransferError
import raftmover.transport as transport
from test_security import add, initial_handoff, pair, rows


def test_declined_stage_does_not_block_new_manual_adoption(tmp_path, monkeypatch):
    sender, receiver, paths, _ = pair(tmp_path)
    initial_handoff(sender, receiver)
    add(paths[0], "first")
    with sender.locked():
        sender.send()
        declined_id = sender._state("chat-state")["packet"]
    with monkeypatch.context() as patch:
        patch.setattr(receiver, "_finish_adoption", lambda *args, **kwargs:
                      (_ for _ in ()).throw(OSError("disk full")))
        with receiver.locked():
            receiver.pickup()
    add(paths[1], "receiver edit")
    monkeypatch.setattr(receiver.transport, "publish_ack", lambda *args:
                        (_ for _ in ()).throw(TransferError("transport-failed")))
    with receiver.locked():
        assert receiver.recover_accept_current("chat-state")["status"] == "recovered"
    assert (receiver.root / "staged" / "chat-state" / declined_id).is_dir()
    add(paths[0], "second")
    with sender.locked():
        sender.send()
    with receiver.locked():
        receiver.pickup(stage_only=True)
        assert receiver.adopt("chat-state", keep_both=True)["status"] == "adopted"
    assert not (receiver.root / "staged" / "chat-state" / declined_id).exists()
    assert receiver.status()[0]["staged"] == 0
    assert receiver._state("chat-state").get("manual_resolution") is None
    assert rows(paths[1]) == ["base", "first", "second"]


@pytest.mark.parametrize("version,available", [
    ("0.1.3", False), ("0.1.4", True), ("0.1.4.post1", True),
    ("0.1.5rc1", True), ("0.1.5.dev2", True), ("0.1.4+local", True),
    ("0.2.0", False), ("unparseable", False),
])
def test_ward_runtime_check_matches_dependency_range(monkeypatch, version, available):
    monkeypatch.setattr(raftward, "__version__", version)
    if available:
        gate, verify = ward_api()
        assert callable(gate) and callable(verify)
    else:
        with pytest.raises(MoveError, match="raftward-unavailable"):
            ward_api()


def test_retiring_old_decline_preserves_newer_adopted_status(tmp_path):
    engine, _, _, _ = pair(tmp_path)
    packet_id = "f" * 32
    with engine.locked():
        engine._save("chat-state", status="adopted", reason="",
                     manual_resolution=packet_id)
        engine._retire_declined(packet_id, {"status": "declined",
                                           "ack_published": True,
                                           "raft": "chat-state"})
        state = engine._state("chat-state")
    assert state["status"] == "adopted"
    assert state["reason"] == ""
    assert state["manual_resolution"] is None


def test_declined_ack_saved_before_interruption_retires_on_retry(tmp_path, monkeypatch):
    sender, receiver, paths, _ = pair(tmp_path)
    initial_handoff(sender, receiver)
    add(paths[0], "incoming")
    with sender.locked():
        sender.send()
        packet_id = sender._state("chat-state")["packet"]
    with monkeypatch.context() as patch:
        patch.setattr(receiver, "_finish_adoption", lambda *args, **kwargs:
                      (_ for _ in ()).throw(OSError("disk full")))
        with receiver.locked():
            receiver.pickup()
    add(paths[1], "local edit")
    with monkeypatch.context() as patch:
        patch.setattr(receiver, "_retire_declined", lambda *args:
                      (_ for _ in ()).throw(OSError("interrupted")))
        with receiver.locked():
            receiver.recover_accept_current("chat-state")
    assert json.loads(receiver._receipt(packet_id).read_text())["ack_published"]
    assert (receiver.root / "staged" / "chat-state" / packet_id).exists()
    assert receiver.status()[0]["status"] == "held"
    with receiver.locked():
        receiver.pickup()
    assert not (receiver.root / "staged" / "chat-state" / packet_id).exists()
    assert receiver.status()[0]["status"] == "recovered"
    assert receiver.status()[0]["staged"] == 0
    assert rows(paths[1])[-1] == "local edit"


def test_old_incomplete_folder_is_swept_but_recent_one_is_held(tmp_path):
    engine, _, _, shared = pair(tmp_path)
    incoming = shared / "incoming"
    incoming.mkdir(mode=0o700)
    old = incoming / ("a" * 32)
    recent = incoming / ("b" * 32)
    for folder in (old, recent):
        folder.mkdir(mode=0o700)
        snapshot = folder / "snapshot.sqlite"
        snapshot.write_bytes(b"partial")
        snapshot.chmod(0o600)
    age = time.time() - 9 * 86400
    os.utime(old, (age, age))
    assert engine.transport.packet_ids() == []
    assert not old.exists()
    assert recent.exists()
    assert engine.transport.held_packets == [{"raft": "packet", "status": "held",
                                              "reason": "incomplete-packet"}]
    assert cli._exit_code(engine.transport.held_packets) == 3


@pytest.mark.parametrize("remote,config", [
    (":sftp:host", {}),
    ("chunks:rafts", {"chunks": {"type": "chunker", "remote": "peer:rafts"},
                       "peer": {"type": "sftp"}}),
    ("union:rafts", {"union": {"type": "union", "upstreams": "peer:rafts"},
                      "peer": {"type": "sftp"}}),
    ("crypt:rafts", {"crypt": {"type": "crypt", "remote": "chunks:rafts"},
                      "chunks": {"type": "chunker", "remote": "peer:rafts"},
                      "peer": {"type": "sftp"}}),
])
def test_inline_or_virtual_remote_cannot_bypass_sftp_check(monkeypatch, remote, config):
    providers = [{"Prefix": name, "Overview": {"Virtual": name != "sftp"}}
                 for name in ("sftp", "crypt", "chunker", "union")]

    def command(argv, timeout=300):
        if argv[1:3] == ["config", "dump"]:
            return json.dumps(config).encode()
        if argv[1:3] == ["config", "providers"]:
            return json.dumps(providers).encode()
        pytest.fail("transport command must not run")

    monkeypatch.setattr(transport, "_command", command)
    with pytest.raises(TransferError, match="transport-config-unverifiable"):
        Rclone(remote).packet_ids()


def test_wrapped_sftp_requires_host_key_and_pickup_keeps_specific_reason(
        tmp_path, monkeypatch):
    engine, _, _, _ = pair(tmp_path)
    config = {"sealed": {"type": "crypt", "remote": "peer:rafts"},
              "peer": {"type": "sftp"}}
    providers = [{"Prefix": "crypt", "Overview": {"Virtual": True}},
                 {"Prefix": "sftp", "Overview": {"Virtual": False}}]

    def command(argv, timeout=300):
        if argv[1:3] == ["config", "dump"]:
            return json.dumps(config).encode()
        if argv[1:3] == ["config", "providers"]:
            return json.dumps(providers).encode()
        pytest.fail("transport command must not run")

    monkeypatch.setattr(transport, "_command", command)
    engine.transport = Rclone("sealed:rafts")
    with engine.locked():
        pickup = engine.pickup()
        send = engine.send()
    assert pickup[0]["reason"] == send[0]["reason"] == "sftp-host-key-unverified"
    assert cli._exit_code(pickup) == cli._exit_code(send) == 3


@pytest.mark.parametrize("remote,config", [
    ("peer:rafts", {"peer": {"type": "sftp", "known_hosts_file": "/verified/hosts"}}),
    ("sealed:rafts", {"sealed": {"type": "crypt", "remote": "peer:rafts"},
                       "peer": {"type": "sftp", "known_hosts_file": "/verified/hosts"}}),
    ("sealed:rafts", {"sealed": {"type": "crypt", "remote": "cloud:rafts"},
                       "cloud": {"type": "onedrive"}}),
])
def test_verified_direct_and_wrapped_remotes_pass_preflight(monkeypatch, remote, config):
    providers = [{"Prefix": "crypt", "Overview": {"Virtual": True}},
                 {"Prefix": "sftp", "Overview": {"Virtual": False}},
                 {"Prefix": "onedrive", "Overview": {"Virtual": False}}]

    def command(argv, timeout=300):
        if argv[1:3] == ["config", "dump"]:
            return json.dumps(config).encode()
        if argv[1:3] == ["config", "providers"]:
            return json.dumps(providers).encode()
        pytest.fail("preflight must not contact the remote")

    monkeypatch.setattr(transport, "_command", command)
    candidate = Rclone(remote)
    candidate._preflight()
    assert candidate._checked_config is True


@pytest.mark.parametrize("reason", ["owning-app-running", "sent-source-state-unverified"])
def test_unchanged_run_clears_prior_temporary_hold(tmp_path, reason):
    engine, _, _, _ = pair(tmp_path)
    with engine.locked():
        assert engine.send()[0]["status"] == "sent"
        engine._save("chat-state", status="held", reason=reason)
        assert engine.send()[0]["status"] == "unchanged"
    assert engine.status()[0]["status"] == "unchanged"
    assert engine.status()[0]["reason"] == ""


def test_unknown_packet_id_and_inconclusive_app_state_exit_codes(tmp_path):
    sender, receiver, _, _ = pair(tmp_path)
    initial_handoff(sender, receiver)
    with receiver.locked():
        with pytest.raises(MoveError, match="no-staged-packet"):
            receiver.adopt("chat-state", "f" * 32)
    assert cli._exit_code([{"raft": "chat-state", "status": "held",
                            "reason": "app-database-state-unknown"}]) == 4
