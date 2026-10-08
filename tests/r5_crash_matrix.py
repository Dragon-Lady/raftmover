"""Crash the receiver at each adoption stage, then recover in a new process."""
import json, os, signal, sqlite3, sys, shutil, subprocess
from contextlib import closing
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import raftmover.engine as em
from raftmover.engine import Engine
from raftward.api import Result

def engines(tmp):
    key = tmp / "pair.key"; paths = [tmp / "a.sqlite", tmp / "b.sqlite"]; out = []
    for label, peer, path in zip(("A", "B"), ("B", "A"), paths):
        cfg = {"machine_label": label, "peer_label": peer,
               "transport": {"kind": "folder", "path": tmp / "shared"},
               "apps": {"chat": {"processes": ["unlikely-test-owner"]}},
               "rafts": [{"label": "chat-state", "kind": "sqlite", "path": path, "app": "chat"}],
               "stage_only": False, "user_idle_minutes": 30, "keep_last_n": 5}
        e = Engine(cfg, tmp / (label + "-state"), key_path=key)
        e.gate = lambda *a, **k: Result("pass", "ok"); out.append(e)
    return out[0], out[1], paths

def add(p, v):
    with closing(sqlite3.connect(p)) as db:
        db.execute("INSERT INTO chat VALUES (?)", (v,)); db.commit()

def rows(p):
    with closing(sqlite3.connect(p)) as db:
        return [v for (v,) in db.execute("SELECT body FROM chat ORDER BY rowid")]

def setup(tmp):
    (tmp / "shared").mkdir(mode=0o700)
    k = tmp / "pair.key"; k.write_bytes(os.urandom(32)); k.chmod(0o600)
    with sqlite3.connect(tmp / "a.sqlite") as db:
        db.execute("CREATE TABLE chat (body TEXT)"); db.execute("INSERT INTO chat VALUES ('base')")
    shutil.copyfile(tmp / "a.sqlite", tmp / "b.sqlite")
    a, b, paths = engines(tmp)
    with a.locked(): a.send()
    with b.locked(): b.pickup(); b.adopt("chat-state", keep_both=True)
    add(paths[0], "sender-new")
    with a.locked(): assert a.send()[0]["status"] == "sent"
    with b.locked(): b.pickup(stage_only=True)

def die():
    os.kill(os.getpid(), signal.SIGKILL)

def crash(tmp, stage):
    a, b, paths = engines(tmp)
    n = {"copy": 0}
    real_copy, real_write, real_replace, real_remove = em.copy_private, em._json_write, os.replace, em.remove_run
    def copy(src, dst):
        real_copy(src, dst); n["copy"] += 1
        if stage == "after-backup" and n["copy"] == 1: die()
        if stage == "after-temp" and n["copy"] == 2: die()
    def write(path, data):
        real_write(path, data)
        if stage == "after-pending" and data.get("status") == "pending": die()
        if stage == "after-lineage" and path.parent.name == "lineage" and data.get("status") == "adopted": die()
        if stage == "after-applied" and data.get("status") == "applied" and "ack_published" in data and not data["ack_published"]: die()
        if stage == "after-ack-flag" and data.get("ack_published") is True: die()
    def replace(src, dst, *x, **k):
        r = real_replace(src, dst, *x, **k)
        if stage == "after-rename" and k.get("dst_dir_fd") is not None and dst == paths[1].name: die()
        return r
    def remove(p):
        real_remove(p)
        if stage == "after-stage-removed" and p.parent.name == "chat-state" and p.parent.parent.name == "staged": die()
    em.copy_private, em._json_write, em.remove_run = copy, write, remove
    os.replace = replace
    with b.locked():
        print(b.pickup())
    print("NO-CRASH")

def recover(tmp, edit):
    a, b, paths = engines(tmp)
    temps = sorted(p.name for p in paths[1].parent.glob(".raftmover-*"))
    pre_rows = rows(paths[1])
    if edit:
        add(paths[1], "receiver-edit-after-crash")
    out = {"rows_after_crash": pre_rows, "temps_after_crash": len(temps)}
    with b.locked():
        out["recovery"] = b.recovery_rows
        out["pickup"] = b.pickup()
        out["status"] = b.status()
    out["rows_final"] = rows(paths[1])
    out["temps_final"] = len(list(paths[1].parent.glob(".raftmover-*")))
    out["backups"] = len(list((b.root / "backups").iterdir()))
    # sender side: does the ack arrive and does a further send work?
    with a.locked():
        a.pickup()
        rec = [json.loads(p.read_text()) for p in (a.root / "receipts").glob("*.json")]
    out["sender_acked"] = sum(1 for r in rec if r.get("acked"))
    print(json.dumps(out))

if __name__ == "__main__":
    tmp = Path(sys.argv[2]); mode = sys.argv[1]
    if mode == "setup": setup(tmp)
    elif mode == "crash": crash(tmp, sys.argv[3])
    else: recover(tmp, mode == "recover-edit")
