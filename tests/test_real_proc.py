"""Host process gate: one running owner holds only its own database."""
import os
import sqlite3
import subprocess
import time

from raftmover.engine import Engine


def test_real_proc_owner_blocks_one_raft_without_touching_it(tmp_path):
    marker = "raftmover-probe-owner"
    process = subprocess.Popen(["bash", "-c", f"exec -a {marker} sleep 30"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(50):
            try:
                command = open(f"/proc/{process.pid}/cmdline", "rb").read(256)
            except FileNotFoundError:
                command = b""
            if marker.encode() in command:
                break
            time.sleep(0.01)
        else:
            raise AssertionError("test owner did not start")
        shared = tmp_path / "shared"
        shared.mkdir(mode=0o700)
        key = tmp_path / "pair.key"
        key.write_bytes(os.urandom(32))
        key.chmod(0o600)
        blocked, free = tmp_path / "blocked.sqlite", tmp_path / "free.sqlite"
        for path in (blocked, free):
            with sqlite3.connect(path) as db:
                db.execute("CREATE TABLE t(x)")
        cfg = {"machine_label": "A", "peer_label": "B",
               "transport": {"kind": "folder", "path": shared},
               "apps": {"running": {"processes": [marker]},
                        "closed": {"processes": ["no-such-raftmover-test-app"]}},
               "rafts": [{"label": "blocked", "kind": "sqlite", "path": blocked,
                          "app": "running"},
                         {"label": "free", "kind": "sqlite", "path": free,
                          "app": "closed"}],
               "stage_only": False, "user_idle_minutes": 30}
        engine = Engine(cfg, tmp_path / "state", key_path=key)
        before = blocked.stat()
        with engine.locked():
            outcome = engine.send()
        after = blocked.stat()
        assert outcome[0] == {"raft": "blocked", "status": "held",
                              "reason": "owning-app-running"}
        assert outcome[1]["status"] == "sent"
        assert (before.st_atime_ns, before.st_mtime_ns) == (
            after.st_atime_ns, after.st_mtime_ns)
    finally:
        process.terminate()
        process.wait(timeout=5)
