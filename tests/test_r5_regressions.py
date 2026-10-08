"""Safe regression versions of the supplied r5 adversarial cases."""
import json
import os
import signal
import sqlite3
import subprocess
import sys
import time

import pytest

from raftmover import app_close, cli, idle
from raftmover.app_close import CloseError
from raftward.api import Result
from test_security import add, initial_handoff, pair, rows


def _bad_ack(engine, packet_id, folder):
    value = engine._ack_payload(packet_id, "chat-state", "0" * 64, "A", "B")
    value["mac"] = "é" * 64
    path = folder / "incoming" / packet_id / "ack.json"
    path.write_text(json.dumps(value))
    path.chmod(0o600)


def test_C1_bad_ack_does_not_crash_pickup_or_block_later_send(tmp_path, monkeypatch, capsys):
    a, _, paths, shared = pair(tmp_path)
    with a.locked():
        assert a.send()[0]["status"] == "sent"
        first = a._state("chat-state")["packet"]
    _bad_ack(a, first, shared)
    add(paths[0], "later")
    monkeypatch.setattr(cli, "load", lambda _: a.cfg)
    monkeypatch.setattr(cli, "Engine", lambda *args, **kwargs: a)
    assert cli.main([]) == 0
    assert "runtime-error" not in capsys.readouterr().err
    assert a._state("chat-state")["packet"] != first
    with a.locked():
        assert a.pickup() == []


def test_C1c_bad_preplanted_ack_does_not_relabel_applied_database(tmp_path):
    a, b, paths, shared = pair(tmp_path)
    initial_handoff(a, b)
    add(paths[0], "second")
    with a.locked():
        a.send()
        packet_id = a._state("chat-state")["packet"]
    _bad_ack(a, packet_id, shared)
    with b.locked():
        outcome = b.pickup()
    assert rows(paths[1]) == ["base", "second"]
    assert outcome[0]["status"] == "adopted"
    with b.locked():
        assert b.pickup() == []


def test_C2_partial_packet_deletion_retries(tmp_path):
    a, b, paths, shared = pair(tmp_path)
    a.cfg["keep_last_n"] = 1
    first = initial_handoff(a, b)
    with a.locked():
        a.pickup()
    add(paths[0], "second")
    with a.locked():
        a.send()
    with b.locked():
        b.pickup()
    (shared / "incoming" / first / "snapshot.sqlite").unlink()
    with a.locked():
        a.pickup()
    assert not (shared / "incoming" / first).exists()
    assert json.loads(a._receipt(first).read_text())["status"] == "retired"


def test_S1_open_during_upload_keeps_lineage_and_receiver_progresses(tmp_path):
    a, b, paths, shared = pair(tmp_path)
    initial_handoff(a, b)
    add(paths[0], "first change")
    real_send = a.transport.send
    opened = {"yes": False}

    def upload(packet, packet_id):
        real_send(packet, packet_id)
        opened["yes"] = True

    a.transport.send = upload
    a.gate = lambda *args, **kwargs: Result(
        "fail", "owning-app-running") if opened["yes"] else Result("pass", "ok")
    with a.locked():
        outcome = a.send()
        first = a._state("chat-state")["packet"]
    assert outcome[0]["status"] == "held"
    assert a._state("chat-state")["last_hash"] is not None
    assert json.loads(a._receipt(first).read_text())["status"] == "own"
    opened["yes"] = False
    a.transport.send = real_send
    add(paths[0], "second change")
    with a.locked():
        assert a.send()[0]["status"] == "sent"
    with b.locked():
        outcome = b.pickup()
    assert [row["status"] for row in outcome] == ["adopted", "adopted"]
    assert rows(paths[1]) == ["base", "first change", "second change"]


def test_S1b_same_bytes_after_upload_do_not_make_sibling(tmp_path):
    a, _, paths, shared = pair(tmp_path)
    add(paths[0], "change")
    real_send = a.transport.send
    opened = {"yes": False}

    def upload(packet, packet_id):
        real_send(packet, packet_id)
        opened["yes"] = True

    a.transport.send = upload
    a.gate = lambda *args, **kwargs: Result(
        "fail", "owning-app-running") if opened["yes"] else Result("pass", "ok")
    with a.locked():
        assert a.send()[0]["status"] == "held"
    opened["yes"] = False
    a.transport.send = real_send
    with a.locked():
        assert a.send()[0]["status"] == "unchanged"
    assert len(list((shared / "incoming").iterdir())) == 1


_TREE = r'''
import ctypes, os, signal, sys, time
name = b"rmr5dummy"
ctypes.CDLL(None).prctl(15, name, 0, 0, 0)
root = os.getpid()
for _ in range(2):
    if os.fork() == 0:
        signal.signal(signal.SIGTERM, lambda *_: open(sys.argv[1], "a").write("child\n"))
        while True: time.sleep(0.1)
def stop(*_):
    with open(sys.argv[1], "a") as stream: stream.write("root\n")
    os._exit(0)
signal.signal(signal.SIGTERM, stop)
while True: time.sleep(0.1)
'''


@pytest.mark.skipif(not hasattr(os, "pidfd_open"), reason="requires Linux pidfd")
def test_A1_close_signals_only_one_root_in_real_process_tree(tmp_path):
    script = tmp_path / "tree.py"
    script.write_text(_TREE)
    log = tmp_path / "term.log"
    proc = subprocess.Popen([sys.executable, str(script), str(log)], start_new_session=True)
    try:
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if (root := app_close._read_process(proc.pid)) and root.comm == "rmr5dummy":
                break
            time.sleep(0.05)
        else:
            pytest.fail("dummy process did not start")
        db = tmp_path / "db.sqlite"
        with sqlite3.connect(db) as conn:
            conn.execute("CREATE TABLE t(x)")
        old = time.time() - 60
        os.utime(db, (old, old))
        app = {"processes": ["rmr5dummy"], "quit": "signal:TERM",
               "exe": os.path.realpath(sys.executable), "app_idle_minutes": 0.002,
               "cpu_idle_pct": 50, "busy_processes": [], "close_timeout_s": 3}

        class Engine:
            cfg = {"apps": {"dummy": app}}

            def _check_gate(self, _raft):
                if app_close._read_process(proc.pid) is not None:
                    raise Exception("owning-app-running")

        assert app_close.close_if_idle(Engine(), "dummy", [{"path": db}])
        assert log.read_text().splitlines() == ["root"]
    finally:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait(timeout=3)


def test_A2_app_without_rafts_cannot_be_closed(monkeypatch):
    monkeypatch.setattr(app_close, "_sample", lambda *args: pytest.fail("must not sample"))
    class Engine:
        cfg = {"apps": {"unused": {"quit": "signal:TERM"}}}
    assert app_close.close_if_idle(Engine(), "unused", []) is False


def test_A6_zero_logind_idle_timestamp_is_unknown(monkeypatch):
    monkeypatch.delenv("XDG_SESSION_ID", raising=False)
    monkeypatch.setattr(idle.subprocess, "run", lambda *args, **kwargs:
                        subprocess.CompletedProcess(args, 0,
                            "IdleHint=yes\nIdleSinceHintMonotonic=0\n", ""))
    assert idle.user_idle_state(30) == "unknown"
    assert idle.user_idle(30) is False


def test_manual_packet_selector_and_backup_status(tmp_path):
    a, b, paths, _ = pair(tmp_path)
    first = initial_handoff(a, b)
    status = b.status()[0]
    assert status["backup_count"] >= 1 and status["backup_bytes"] > 0
    assert cli._args(["adopt", "chat-state", "--packet", first]).packet == first


def test_status_formats_include_backup_usage(tmp_path, capsys):
    a, b, _, _ = pair(tmp_path)
    initial_handoff(a, b)
    status = b.status()
    for fmt in ("text", "json", "md", "html"):
        cli._print_rows(status, fmt)
        output = capsys.readouterr().out
        assert str(status[0]["backup_count"]) in output
        assert str(status[0]["backup_bytes"]) in output


def test_accept_current_signs_decline_and_retires_stage(tmp_path, monkeypatch):
    a, b, paths, shared = pair(tmp_path)
    initial_handoff(a, b)
    add(paths[0], "incoming")
    with a.locked():
        a.send()
        packet_id = a._state("chat-state")["packet"]
    with monkeypatch.context() as patch:
        patch.setattr(b, "_finish_adoption", lambda *args, **kwargs:
                      (_ for _ in ()).throw(OSError("disk full")))
        with b.locked():
            b.pickup()
    add(paths[1], "local edit")
    with b.locked():
        assert b.recover_accept_current("chat-state")["status"] == "recovered"
        assert b.recover_accept_current("chat-state")["status"] == "recovered"
        assert not any(row["reason"] == "current-kept-after-review"
                       for row in b.pickup())
    receipt = json.loads(b._receipt(packet_id).read_text())
    assert receipt["status"] == "declined" and receipt["ack_published"]
    assert not (b.root / "staged" / "chat-state" / packet_id).exists()
    assert b.status()[0]["status"] == "recovered"
    assert b.status()[0]["staged"] == 0
    with a.locked():
        a.pickup()
    assert json.loads(a._receipt(packet_id).read_text())["acked"] is True
    assert rows(paths[1])[-1] == "local edit"


def test_folder_sweeps_old_partial_and_ack_hardlink(tmp_path):
    a, b, _, shared = pair(tmp_path)
    first = initial_handoff(a, b)
    incoming = shared / "incoming"
    partial = incoming / (".partial-" + "f" * 32)
    partial.mkdir(mode=0o700)
    old = time.time() - 9 * 86400
    os.utime(partial, (old, old))
    packet = incoming / first
    temporary = packet / (".ack-" + "e" * 16)
    os.link(packet / "ack.json", temporary)
    run = tmp_path / "fetch"
    run.mkdir(mode=0o700)
    a.transport.fetch_ack(first, run)
    assert not temporary.exists()
    assert (run / "ack.json").exists()
    a.transport.packet_ids()
    assert not partial.exists()


def test_retention_removes_orphan_ack_temp_after_verified_ack(tmp_path):
    a, b, paths, shared = pair(tmp_path)
    a.cfg["keep_last_n"] = 1
    first = initial_handoff(a, b)
    with a.locked():
        a.pickup()
    add(paths[0], "second")
    with a.locked():
        a.send()
    with b.locked():
        b.pickup()
    packet = shared / "incoming" / first
    orphan = packet / (".ack-" + "a" * 16)
    orphan.write_bytes(b"unfinished")
    orphan.chmod(0o600)
    with a.locked():
        a.pickup()
    assert not packet.exists()
