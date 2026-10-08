import os
from pathlib import Path
import shutil
import sqlite3

from raftmover.engine import Engine
from raftward.api import Result


def _cfg(label, db, shared):
    return {"machine_label": label, "peer_label": "B" if label == "A" else "A",
            "transport": {"kind": "folder", "path": shared},
            "apps": {"chat": {"processes": ["unlikely-test-owner-raftmover"]}},
            "rafts": [{"label": "chat-state", "kind": "sqlite", "path": db, "app": "chat"}],
            "stage_only": False, "user_idle_minutes": 30}


def _insert(db, body):
    with sqlite3.connect(db) as conn:
        conn.execute("INSERT INTO chat (body) VALUES (?)", (body,))


def _rows(db):
    with sqlite3.connect(db) as conn:
        return [x[0] for x in conn.execute("SELECT body FROM chat ORDER BY rowid")]


def test_changed_chat_roundtrip_with_manual_first_pair(tmp_path):
    shared = tmp_path / "shared"
    shared.mkdir(mode=0o700)
    a, b = tmp_path / "a.sqlite", tmp_path / "b.sqlite"
    with sqlite3.connect(a) as conn:
        conn.execute("CREATE TABLE chat (body TEXT)")
        conn.execute("INSERT INTO chat VALUES ('base')")
    shutil.copyfile(a, b)
    _insert(a, "from A")
    key = tmp_path / "pair.key"
    key.write_bytes(os.urandom(32))
    key.chmod(0o600)
    sender = Engine(_cfg("A", a, shared), tmp_path / "a-state", key_path=key)
    receiver = Engine(_cfg("B", b, shared), tmp_path / "b-state", key_path=key)
    # Isolate the local copy/lineage path; Raft Ward's real frozen-copy
    # verification still runs twice for every handoff.
    for engine in (sender, receiver):
        engine.gate = lambda *args, **kwargs: Result("pass", "ok")
    with sender.locked():
        assert sender.send()[0]["status"] == "sent"
    with receiver.locked():
        result = receiver.pickup()
        assert result[0]["status"] == "staged"
        assert _rows(b) == ["base"]
        assert receiver.adopt("chat-state", keep_both=True)["status"] == "adopted"
    assert _rows(b) == ["base", "from A"]
    _insert(b, "from B")
    with receiver.locked():
        assert receiver.send()[0]["status"] == "sent"
    with sender.locked():
        result = sender.pickup()
        assert any(r["status"] == "adopted" for r in result), result
    assert _rows(a) == ["base", "from A", "from B"]


def test_owner_running_does_not_touch_its_db(tmp_path):
    shared = tmp_path / "shared"
    shared.mkdir(mode=0o700)
    blocked, free = tmp_path / "blocked.sqlite", tmp_path / "free.sqlite"
    for db in (blocked, free):
        with sqlite3.connect(db) as conn:
            conn.execute("CREATE TABLE t (x)")
    cfg = _cfg("A", free, shared)
    cfg["rafts"].insert(0, {"label": "blocked", "kind": "sqlite", "path": blocked, "app": "chat"})
    key = tmp_path / "pair.key"
    key.write_bytes(os.urandom(32))
    key.chmod(0o600)
    engine = Engine(cfg, tmp_path / "state", key_path=key)
    def gate(path, owners, **kwargs):
        if Path(path) == blocked:
            return Result("fail", "owning-app-running")
        return Result("pass", "ok")
    engine.gate = gate
    before = blocked.stat()
    with engine.locked():
        rows = engine.send()
    assert rows[0] == {"raft": "blocked", "status": "held", "reason": "owning-app-running"}
    assert rows[1]["status"] == "sent"
    after = blocked.stat()
    assert (before.st_atime_ns, before.st_mtime_ns) == (after.st_atime_ns, after.st_mtime_ns)
