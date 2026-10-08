"""The opt-in close path may signal only a verified idle main process."""
import os
import signal
import sqlite3

import pytest

from raftmover import app_close, cli
from raftmover.app_close import CloseError, Process
from raftmover.engine import MoveError
from raftward.api import Result
from test_security import pair


def _process(pid, comm, ticks=0, parent=1):
    return Process(pid, parent, os.getuid(), comm, comm, "/usr/bin/" + comm,
                   12345 + pid, ticks)


def test_close_sends_term_only_to_verified_main_process(monkeypatch):
    main, worker = _process(123, "chat"), _process(124, "helper", parent=123)
    later = {123: _process(123, "chat", ticks=5),
             124: _process(124, "helper", ticks=5, parent=123)}
    first = {123: main, 124: worker}
    samples = iter([(first, {123}, {123, 124}, {123}, ("same",)),
                    (later, {123}, {123, 124}, {123}, ("same",))])
    monkeypatch.setattr(app_close, "_sample", lambda *args: next(samples))
    monkeypatch.setattr(app_close, "_read_process", lambda pid: later[pid])
    now = [0]
    monkeypatch.setattr(app_close.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(app_close.time, "sleep", lambda duration: now.__setitem__(0, now[0] + duration))
    monkeypatch.setattr(app_close.os, "pidfd_open", lambda pid: os.open("/dev/null", os.O_RDONLY))
    sent = []
    monkeypatch.setattr(app_close.signal, "pidfd_send_signal",
                        lambda fd, sig: sent.append(sig))

    class Engine:
        cfg = {"apps": {"chat": {"processes": ["chat", "helper"],
                                 "quit": "signal:TERM", "exe": "/usr/bin/chat",
                                 "app_idle_minutes": 1,
                                 "cpu_idle_pct": 3, "close_timeout_s": 2,
                                 "busy_processes": ["agent-worker"]}}}

        def _check_gate(self, raft):
            if not sent:
                raise MoveError("owning-app-running")

    assert app_close.close_if_idle(Engine(), "chat", [{"path": "unused"}],
                                  auto=True, user_idle=lambda: True) is True
    assert sent == [signal.SIGTERM]


def test_close_refuses_changed_process_before_signaling(monkeypatch):
    main = _process(123, "chat")
    samples = iter([({123: main}, {123}, {123}, {123}, ("same",)),
                    ({123: main}, {123}, {123}, {123}, ("same",))])
    monkeypatch.setattr(app_close, "_sample", lambda *args: next(samples))
    monkeypatch.setattr(app_close, "_read_process", lambda pid: _process(pid, "chat", ticks=0))
    now = [0]
    monkeypatch.setattr(app_close.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(app_close.time, "sleep", lambda duration: now.__setitem__(0, now[0] + duration))
    monkeypatch.setattr(app_close.os, "pidfd_open", lambda pid: os.open("/dev/null", os.O_RDONLY))
    sent = []
    monkeypatch.setattr(app_close.signal, "pidfd_send_signal",
                        lambda fd, sig: sent.append(sig))

    class Engine:
        cfg = {"apps": {"chat": {"processes": ["chat"], "quit": "signal:TERM",
                                 "exe": "/usr/bin/chat",
                                 "app_idle_minutes": 1, "cpu_idle_pct": 3,
                                 "close_timeout_s": 2, "busy_processes": []}}}

        def _check_gate(self, raft):
            raise MoveError("owning-app-running")

    # The second sample's identity is stable; the final pidfd-bound reread is not.
    monkeypatch.setattr(app_close, "_read_process",
                        lambda pid: Process(pid, 1, os.getuid(), "chat", "chat",
                                            "/usr/bin/chat", 99999, 0))
    with pytest.raises(CloseError, match="app-process-changed"):
        app_close.close_if_idle(Engine(), "chat", [{"path": "unused"}])
    assert sent == []


def test_one_busy_app_does_not_block_another_raft(tmp_path, monkeypatch, capsys):
    sender, _, paths, _ = pair(tmp_path)
    blocked = tmp_path / "blocked.sqlite"
    with sqlite3.connect(blocked) as db:
        db.execute("CREATE TABLE t(x)")
    sender.cfg["apps"]["busy"] = {"processes": ["busy"]}
    sender.cfg["rafts"].insert(0, {"label": "busy-state", "kind": "sqlite",
                                     "path": blocked, "app": "busy"})
    sender.gate = lambda path, *_args, **_kwargs: (
        Result("fail", "owning-app-running") if path == blocked else Result("pass", "ok"))
    before = blocked.stat()
    monkeypatch.setattr(cli, "load", lambda _: sender.cfg)
    monkeypatch.setattr(cli, "Engine", lambda *args, **kwargs: sender)

    def close(_engine, name, _rafts, **kwargs):
        if name == "busy":
            raise CloseError("app-worker-busy")
        return False

    monkeypatch.setattr(cli, "close_if_idle", close)
    assert cli.main(["--close"]) == 3
    output = capsys.readouterr().out
    assert "busy-state: held (app-worker-busy)" in output
    assert "chat-state: sent" in output
    after = blocked.stat()
    assert (before.st_atime_ns, before.st_mtime_ns) == (after.st_atime_ns, after.st_mtime_ns)


def test_timer_not_idle_never_closes_or_reads_database(tmp_path, monkeypatch):
    sender, _, paths, _ = pair(tmp_path)
    before = paths[0].stat()
    monkeypatch.setattr(cli, "load", lambda _: sender.cfg)
    monkeypatch.setattr(cli, "Engine", lambda *args, **kwargs: sender)
    monkeypatch.setattr(cli, "user_idle", lambda minutes: False)
    monkeypatch.setattr(cli, "user_idle_state", lambda minutes: "active")
    monkeypatch.setattr(cli, "close_if_idle", lambda *args, **kwargs: (
        _ for _ in ()).throw(AssertionError("must not close")))
    assert cli.main(["--auto"]) == 3
    after = paths[0].stat()
    assert (before.st_atime_ns, before.st_mtime_ns) == (
        after.st_atime_ns, after.st_mtime_ns)
    assert not sender.root.exists()


def test_busy_child_holds_close_before_any_signal(tmp_path, monkeypatch):
    db = tmp_path / "chat.sqlite"
    with sqlite3.connect(db) as conn:
        conn.execute("CREATE TABLE t(x)")
    old = (app_close.time.time_ns() - 20 * 60 * 1_000_000_000) / 1_000_000_000
    os.utime(db, (old, old))
    main = _process(100, "chat")
    busy = _process(101, "chat-agent", parent=100)
    monkeypatch.setattr(app_close, "_processes", lambda: {100: main, 101: busy})
    app = {"processes": ["chat"], "quit": "signal:TERM", "exe": "/usr/bin/chat",
           "app_idle_minutes": 10,
           "cpu_idle_pct": 3, "busy_processes": ["chat-agent"], "close_timeout_s": 2}
    with pytest.raises(CloseError, match="app-worker-busy"):
        app_close._sample(app, [{"path": db}], 600)
