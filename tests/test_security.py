import hashlib
import errno
import json
import os
from pathlib import Path
import shutil
import sqlite3
from contextlib import closing

import pytest

import raftmover.engine as engine_module
from raftmover.engine import Engine, MoveError
from raftmover.transport import Folder, TransferError
from raftward.api import Result


def pair(tmp):
    shared = tmp / "shared"
    shared.mkdir(mode=0o700)
    key = tmp / "pair.key"
    key.write_bytes(os.urandom(32))
    key.chmod(0o600)
    paths = [tmp / "a.sqlite", tmp / "b.sqlite"]
    with sqlite3.connect(paths[0]) as db:
        db.execute("CREATE TABLE chat (body TEXT)")
        db.execute("INSERT INTO chat VALUES ('base')")
    shutil.copyfile(paths[0], paths[1])
    engines = []
    for label, peer, path in zip(("A", "B"), ("B", "A"), paths):
        cfg = {"machine_label": label, "peer_label": peer,
               "transport": {"kind": "folder", "path": shared},
               "apps": {"chat": {"processes": ["unlikely-test-owner"]}},
               "rafts": [{"label": "chat-state", "kind": "sqlite", "path": path,
                          "app": "chat"}], "stage_only": False, "user_idle_minutes": 30}
        engine = Engine(cfg, tmp / (label + "-state"), key_path=key)
        engine.gate = lambda *a, **k: Result("pass", "ok")
        engines.append(engine)
    return engines[0], engines[1], paths, shared


def add(path, value):
    with closing(sqlite3.connect(path)) as db:
        db.execute("INSERT INTO chat VALUES (?)", (value,))
        db.commit()


def rows(path):
    with closing(sqlite3.connect(path)) as db:
        return [v for (v,) in db.execute("SELECT body FROM chat ORDER BY rowid")]


def initial_handoff(a, b):
    with a.locked():
        assert a.send()[0]["status"] == "sent"
        packet_id = a._state("chat-state")["packet"]
    with b.locked():
        assert b.pickup()[0]["status"] == "staged"
        assert b.adopt("chat-state", keep_both=True)["status"] == "adopted"
    return packet_id


def test_forged_packet_is_rejected_before_adoption(tmp_path):
    a, b, paths, shared = pair(tmp_path)
    initial_handoff(a, b)
    before = paths[1].read_bytes()
    fake_id = "f" * 32
    folder = shared / "incoming" / fake_id
    folder.mkdir(mode=0o700)
    with sqlite3.connect(folder / "snapshot.sqlite") as db:
        db.execute("CREATE TABLE chat (body TEXT)")
        db.execute("INSERT INTO chat VALUES ('FORGED by attacker')")
    snapshot = folder / "snapshot.sqlite"
    snapshot.chmod(0o600)
    value = {"format": 1, "id": fake_id, "raft": "chat-state", "source": "A",
             "parent": b._state("chat-state")["last_hash"],
             "sha256": hashlib.sha256(snapshot.read_bytes()).hexdigest(),
             "size": snapshot.stat().st_size, "ward": "pass", "mac": "0" * 64}
    (folder / "manifest.json").write_text(json.dumps(value))
    (folder / "manifest.json").chmod(0o600)
    with b.locked():
        outcome = b.pickup()
    assert any(r["reason"] == "unauthenticated-packet" for r in outcome)
    assert paths[1].read_bytes() == before
    assert "FORGED by attacker" not in repr(outcome)


def test_applied_packet_cannot_be_replayed_by_hand(tmp_path):
    a, b, paths, shared = pair(tmp_path)
    old_id = initial_handoff(a, b)
    add(paths[1], "new message")
    before = paths[1].read_bytes()
    with b.locked():
        with pytest.raises(MoveError, match="packet-already-applied"):
            b.adopt("chat-state", old_id, keep_both=True)
        assert b.pickup() == []
    assert paths[1].read_bytes() == before


def test_failed_database_swap_leaves_packet_retryable(tmp_path, monkeypatch):
    a, b, paths, _ = pair(tmp_path)
    initial_handoff(a, b)
    add(paths[0], "new message")
    with a.locked():
        a.send()
        packet_id = a._state("chat-state")["packet"]
    before = paths[1].read_bytes()
    real_replace = os.replace

    def full_disk_at_swap(src, dst, *args, **kwargs):
        if dst == paths[1].name and kwargs.get("dst_dir_fd") is not None:
            raise OSError(errno.ENOSPC, "full disk")
        return real_replace(src, dst, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(os, "replace", full_disk_at_swap)
        with b.locked():
            assert b.pickup()[0]["status"] == "staged"
            assert not b._consumed(packet_id)
            assert b._receipt(packet_id).exists()
    assert paths[1].read_bytes() == before
    with b.locked():
        assert b.pickup()[0]["status"] == "adopted"
    assert rows(paths[1]) == ["base", "new message"]


def test_completed_swap_with_pending_receipt_is_reconciled(tmp_path, monkeypatch):
    a, b, paths, _ = pair(tmp_path)
    initial_handoff(a, b)
    add(paths[0], "new message")
    with a.locked():
        a.send()
        packet_id = a._state("chat-state")["packet"]
    finish = b._finish_adoption
    with monkeypatch.context() as patch:
        patch.setattr(b, "_finish_adoption", lambda *args: (_ for _ in ()).throw(OSError(errno.ENOSPC, "full disk")))
        with b.locked():
            assert b.pickup()[0]["status"] == "staged"
            assert not b._consumed(packet_id)
    assert rows(paths[1]) == ["base", "new message"]
    b._finish_adoption = finish
    with b.locked():
        assert b._consumed(packet_id)
        assert b._state("chat-state")["packet"] == packet_id
        assert b.pickup()[0]["status"] == "recovered"


def test_saved_swap_receipt_recovers_after_receiver_changes(tmp_path, monkeypatch):
    a, b, paths, _ = pair(tmp_path)
    initial_handoff(a, b)
    add(paths[0], "new message")
    with a.locked():
        a.send()
        packet_id = a._state("chat-state")["packet"]
    with monkeypatch.context() as patch:
        patch.setattr(b, "_mark_hash", lambda *_: (_ for _ in ()).throw(OSError(errno.ENOSPC, "full disk")))
        with b.locked():
            assert b.pickup()[0]["status"] == "staged"
            assert not b._consumed(packet_id)
            assert b._state("chat-state")["packet"] == packet_id
    add(paths[1], "later local edit")
    with b.locked():
        assert b._consumed(packet_id)
        assert b.pickup()[0]["status"] == "recovered"
    assert rows(paths[1]) == ["base", "new message", "later local edit"]


def test_swap_then_edit_keeps_correct_backup_and_pending_receipt(tmp_path, monkeypatch):
    a, b, paths, _ = pair(tmp_path)
    add(paths[1], "older receiver history")
    initial_handoff(a, b)
    older_backup = b._state("chat-state")["backup"]
    add(paths[0], "new message")
    with a.locked():
        a.send()
        packet_id = a._state("chat-state")["packet"]
    with monkeypatch.context() as patch:
        patch.setattr(b, "_finish_adoption",
                      lambda *args: (_ for _ in ()).throw(OSError(errno.ENOSPC, "full disk")))
        with b.locked():
            assert b.pickup()[0]["status"] == "staged"
    pending = json.loads(b._receipt(packet_id).read_text())
    assert pending["backup"] != older_backup
    add(paths[1], "later receiver edit")
    with b.locked():
        assert b.recovery_rows == [{"raft": "chat-state", "status": "held",
                                   "reason": "pending-swap-ambiguous"}]
        assert not b._consumed(packet_id)
        assert b._state("chat-state")["backup"] == pending["backup"]
        assert b._state("chat-state")["lineage_broken"] is True
        assert b.status()[0]["status"] == "pending"
        assert b.status()[0]["reason"] == "pending-swap-ambiguous"
        assert any(r["reason"] == "pending-adoption-recovery-required"
                   for r in b.pickup())
    assert rows(b.root / "backups" / pending["backup"]) == ["base"]
    assert rows(paths[1]) == ["base", "new message", "later receiver edit"]
    with b.locked():
        assert b.restore("chat-state")["status"] == "restored"
    assert rows(paths[1]) == ["base"]
    assert rows(b.root / "backups" / b._state("chat-state")["backup"]) == [
        "base", "new message", "later receiver edit"]
    with b.locked():
        assert any(r["status"] == "staged" for r in b.pickup())
    assert rows(paths[1]) == ["base"]


def test_replace_error_after_landed_swap_does_not_discard_receipt(tmp_path, monkeypatch):
    a, b, paths, _ = pair(tmp_path)
    initial_handoff(a, b)
    add(paths[0], "new message")
    with a.locked():
        a.send()
        packet_id = a._state("chat-state")["packet"]
    real_replace = os.replace

    def rename_then_error(src, dst, *args, **kwargs):
        result = real_replace(src, dst, *args, **kwargs)
        if dst == paths[1].name and kwargs.get("dst_dir_fd") is not None:
            raise OSError(errno.EIO, "rename reported error")
        return result

    with monkeypatch.context() as patch:
        patch.setattr(os, "replace", rename_then_error)
        with b.locked():
            assert b.pickup()[0]["status"] == "staged"
            assert b._receipt(packet_id).exists()
    add(paths[1], "later receiver edit")
    with b.locked():
        assert b.recovery_rows[0]["reason"] == "pending-swap-ambiguous"
        assert not b._consumed(packet_id)
    assert rows(paths[1]) == ["base", "new message", "later receiver edit"]


def test_missing_pending_backup_finishes_with_broken_lineage(tmp_path, monkeypatch):
    a, b, paths, _ = pair(tmp_path)
    initial_handoff(a, b)
    add(paths[0], "new message")
    with a.locked():
        a.send()
        packet_id = a._state("chat-state")["packet"]
    with monkeypatch.context() as patch:
        patch.setattr(b, "_finish_adoption",
                      lambda *args: (_ for _ in ()).throw(OSError(errno.ENOSPC, "full disk")))
        with b.locked():
            b.pickup()
    pending = json.loads(b._receipt(packet_id).read_text())
    (b.root / "backups" / pending["backup"]).unlink()
    with b.locked():
        assert b.recovery_rows[0]["reason"] == "backup-missing-manual-review"
        assert b._consumed(packet_id)
        state = b._state("chat-state")
        assert state["backup"] is None
        assert state["lineage_broken"] is True
    assert rows(paths[1]) == ["base", "new message"]


def test_missing_pending_stage_reports_reason_then_refetches(tmp_path, monkeypatch):
    a, b, paths, _ = pair(tmp_path)
    initial_handoff(a, b)
    add(paths[0], "new message")
    with a.locked():
        a.send()
        packet_id = a._state("chat-state")["packet"]
    with monkeypatch.context() as patch:
        patch.setattr(b, "_finish_adoption",
                      lambda *args: (_ for _ in ()).throw(OSError(errno.EIO, "stop")))
        with b.locked():
            b.pickup()
    stage = b.root / "staged" / "chat-state" / packet_id
    shutil.rmtree(stage)
    with b.locked():
        assert b.recovery_rows[0]["reason"] == "pending-stage-missing"
        b.pickup()
        assert stage.exists()
    with b.locked():
        assert b._consumed(packet_id)
    assert rows(paths[1]) == ["base", "new message"]


def test_orphan_temp_swept_only_after_owner_gate_passes(tmp_path):
    _, b, paths, _ = pair(tmp_path)
    temp = paths[1].parent / (".raftmover-" + "a" * 24)
    temp.write_bytes(b"private abandoned copy")
    temp.chmod(0o600)
    b.gate = lambda *args, **kwargs: Result("fail", "owning-app-running")
    with b.locked():
        assert temp.exists()
    b.gate = lambda *args, **kwargs: Result("pass", "ok")
    with b.locked():
        assert not temp.exists()


def test_orphan_temp_with_receiver_mode_is_swept(tmp_path):
    _, b, paths, _ = pair(tmp_path)
    paths[1].chmod(0o644)
    temp = paths[1].parent / (".raftmover-" + "b" * 24)
    temp.write_bytes(b"abandoned private copy")
    temp.chmod(0o644)
    with b.locked():
        assert not temp.exists()


def test_unswapped_pending_temp_and_receiver_edit_preserve_both(tmp_path, monkeypatch):
    a, b, paths, _ = pair(tmp_path)
    initial_handoff(a, b)
    add(paths[0], "new message")
    with a.locked():
        a.send()
        packet_id = a._state("chat-state")["packet"]
    real_replace, real_unlink = os.replace, Path.unlink

    def failed_swap(src, dst, *args, **kwargs):
        if dst == paths[1].name and kwargs.get("dst_dir_fd") is not None:
            raise OSError(errno.ENOSPC, "full disk")
        return real_replace(src, dst, *args, **kwargs)

    def keep_orphan(self, *args, **kwargs):
        if self.name.startswith(".raftmover-"):
            return None
        return real_unlink(self, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(os, "replace", failed_swap)
        patch.setattr(Path, "unlink", keep_orphan)
        with b.locked():
            assert b.pickup()[0]["status"] == "staged"
    pending = json.loads(b._receipt(packet_id).read_text())
    assert (paths[1].parent / pending["temp"]).exists()
    add(paths[1], "receiver edit")
    with b.locked():
        assert b.recovery_rows[0]["reason"] == "diverged-or-unpaired"
        assert not b._receipt(packet_id).exists()
        assert b._state("chat-state")["backup"] == pending["backup"]
        assert b._state("chat-state")["lineage_broken"] is True
    assert rows(paths[1]) == ["base", "receiver edit"]
    assert rows(b.root / "backups" / pending["backup"]) == ["base"]
    assert not (paths[1].parent / pending["temp"]).exists()


def test_referenced_pending_backup_survives_manual_revert(tmp_path, monkeypatch):
    a, b, paths, _ = pair(tmp_path)
    initial_handoff(a, b)
    add(paths[0], "new message")
    with a.locked():
        a.send()
        packet_id = a._state("chat-state")["packet"]
    with monkeypatch.context() as patch:
        patch.setattr(b, "_finish_adoption",
                      lambda *args: (_ for _ in ()).throw(OSError(errno.ENOSPC, "full disk")))
        with b.locked():
            b.pickup()
    add(paths[1], "receiver edit")
    with b.locked():
        assert b.recovery_rows[0]["reason"] == "pending-swap-ambiguous"
    backup = b.root / "backups" / b._state("chat-state")["backup"]
    shutil.copyfile(backup, paths[1])
    with b.locked():
        assert not b._receipt(packet_id).exists()
        assert backup.exists()
        assert b.restore("chat-state")["status"] == "restored"


def test_missing_backup_and_later_edit_can_keep_current(tmp_path, monkeypatch):
    a, b, paths, _ = pair(tmp_path)
    initial_handoff(a, b)
    add(paths[0], "new message")
    with a.locked():
        a.send()
        packet_id = a._state("chat-state")["packet"]
    with monkeypatch.context() as patch:
        patch.setattr(b, "_finish_adoption",
                      lambda *args: (_ for _ in ()).throw(OSError(errno.ENOSPC, "full disk")))
        with b.locked():
            b.pickup()
    pending = json.loads(b._receipt(packet_id).read_text())
    (b.root / "backups" / pending["backup"]).unlink()
    add(paths[1], "receiver edit")
    with b.locked():
        assert b.recovery_rows[0]["reason"] == "pending-backup-missing"
        before = paths[1].read_bytes()
        assert b.send()[0]["status"] == "held"
        assert b.recover_accept_current("chat-state")["status"] == "recovered"
        assert json.loads(b._receipt(packet_id).read_text())["status"] == "declined"
        state = b._state("chat-state")
        assert state["lineage_broken"] is True
        assert (b.root / "backups" / state["backup"]).read_bytes() == before
    assert paths[1].read_bytes() == before


def test_status_reports_invalid_stage_without_crashing(tmp_path):
    _, b, _, _ = pair(tmp_path)
    with b.locked():
        (b.root / "staged" / "chat-state" / "not-a-packet").mkdir(parents=True)
    row = b.status()[0]
    assert row["status"] == "held" and row["reason"] == "invalid-receipt"


def test_only_acknowledged_old_packet_is_retired(tmp_path):
    a, b, paths, shared = pair(tmp_path)
    a.cfg["keep_last_n"] = 1
    first = initial_handoff(a, b)
    with a.locked():
        a.pickup()
    add(paths[0], "second message")
    with a.locked():
        assert a.send()[0]["status"] == "sent"
        second = a._state("chat-state")["packet"]
    with a.locked():
        a.pickup()
    assert (shared / "incoming" / first).exists()  # second is not acknowledged yet
    with b.locked():
        assert b.pickup()[0]["status"] == "adopted"
    with a.locked():
        a.pickup()
    assert not (shared / "incoming" / first).exists()
    assert (shared / "incoming" / second).exists()
    assert json.loads(a._receipt(first).read_text())["status"] == "retired"
    assert rows(paths[1]) == ["base", "second message"]


def test_forged_ack_never_permits_packet_retirement(tmp_path):
    a, b, _, shared = pair(tmp_path)
    a.cfg["keep_last_n"] = 1
    with a.locked():
        assert a.send()[0]["status"] == "sent"
        packet_id = a._state("chat-state")["packet"]
    fake = shared / "incoming" / packet_id / "ack.json"
    fake.write_text(json.dumps({"id": packet_id, "status": "applied", "mac": "0" * 64}))
    fake.chmod(0o600)
    with a.locked():
        a.pickup()
    assert not json.loads(a._receipt(packet_id).read_text())["acked"]
    assert (shared / "incoming" / packet_id).exists()
    fake.unlink()
    with b.locked():
        assert b.pickup()[0]["status"] == "staged"
        b.adopt("chat-state", keep_both=True)
    with a.locked():
        a.pickup()
    assert json.loads(a._receipt(packet_id).read_text())["acked"] is True


def test_applied_receipt_cleans_stale_stage_and_status(tmp_path, monkeypatch):
    a, b, paths, _ = pair(tmp_path)
    initial_handoff(a, b)
    add(paths[0], "new message")
    with a.locked():
        a.send()
        packet_id = a._state("chat-state")["packet"]
    real_remove = engine_module.remove_run

    def interrupt_stage_removal(path):
        if path.name == packet_id:
            raise OSError(errno.EIO, "interrupted stage cleanup")
        return real_remove(path)

    with monkeypatch.context() as patch:
        patch.setattr(engine_module, "remove_run", interrupt_stage_removal)
        with b.locked():
            b.pickup()
    stage = b.root / "staged" / "chat-state" / packet_id
    assert stage.exists()
    assert b.status()[0]["staged"] == 0
    with b.locked():
        b.pickup()
    assert not stage.exists()


def test_queued_packets_follow_lineage_not_random_ids(tmp_path):
    a, b, paths, shared = pair(tmp_path)
    initial_handoff(a, b)
    add(paths[0], "one")
    with a.locked():
        assert a.send()[0]["status"] == "sent"
    add(paths[0], "two")
    with a.locked():
        assert a.send()[0]["status"] == "sent"
    with b.locked():
        outcome = b.pickup()
    assert [r["status"] for r in outcome] == ["adopted", "adopted"]
    assert rows(paths[1]) == ["base", "one", "two"]


def test_older_unconsumed_ancestor_cannot_roll_back_manual_adoption(tmp_path):
    a, b, paths, shared = pair(tmp_path)
    initial_handoff(a, b)
    add(paths[0], "one")
    with a.locked():
        a.send()
        older = a._state("chat-state")["packet"]
    add(paths[0], "two")
    with a.locked():
        a.send()
        newer = a._state("chat-state")["packet"]
    with b.locked():
        b.pickup(stage_only=True)
        assert b.adopt("chat-state", newer, keep_both=True)["status"] == "adopted"
        with pytest.raises(MoveError, match="packet-already-applied"):
            b.adopt("chat-state", older, keep_both=True)
    assert rows(paths[1]) == ["base", "one", "two"]


def test_symlinked_packet_directory_is_held_while_valid_packet_continues(tmp_path):
    a, b, paths, shared = pair(tmp_path)
    initial_handoff(a, b)
    add(paths[0], "valid message")
    with a.locked():
        a.send()
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    (shared / "incoming" / ("f" * 32)).symlink_to(outside, target_is_directory=True)
    with b.locked():
        outcome = b.pickup()
    assert any(r["reason"] == "unsafe-packet-directory" for r in outcome)
    assert any(r["status"] == "adopted" for r in outcome)
    assert rows(paths[1]) == ["base", "valid message"]


def test_fifo_manifest_cannot_block_packet_pickup(tmp_path):
    a, b, paths, shared = pair(tmp_path)
    initial_handoff(a, b)
    add(paths[0], "valid message")
    with a.locked():
        a.send()
    forged = shared / "incoming" / ("f" * 32)
    forged.mkdir(mode=0o700)
    os.mkfifo(forged / "manifest.json", mode=0o600)
    with b.locked():
        outcome = b.pickup()
    assert any(r["reason"] == "unsafe-packet-file" for r in outcome)
    assert any(r["status"] == "adopted" for r in outcome)
    assert rows(paths[1]) == ["base", "valid message"]


def test_own_packet_is_not_refetched_after_authenticated_manifest(tmp_path, monkeypatch):
    a, b, _, _ = pair(tmp_path)
    with a.locked():
        a.send()
        packet_id = a._state("chat-state")["packet"]
    with monkeypatch.context() as patch:
        patch.setattr(a.transport, "fetch_snapshot",
                      lambda *args: pytest.fail("own snapshot fetched"))
        with a.locked():
            assert a.pickup() == []
            assert a._consumed(packet_id)
            assert a.pickup() == []


def test_lost_applied_receipt_is_restored_without_refetching_snapshot(tmp_path, monkeypatch):
    a, b, paths, _ = pair(tmp_path)
    packet_id = initial_handoff(a, b)
    b._receipt(packet_id).unlink()
    before = paths[1].read_bytes()
    with monkeypatch.context() as patch:
        patch.setattr(b.transport, "fetch_snapshot",
                      lambda *args: pytest.fail("applied snapshot fetched"))
        with b.locked():
            assert b.pickup() == []
            assert b._consumed(packet_id)
    assert paths[1].read_bytes() == before


def test_ward_gate_scopes_transfer_to_database_and_sidecars(tmp_path):
    a, _, paths, _ = pair(tmp_path)
    scopes = []

    def gate(path, owners, **kwargs):
        scopes.append(kwargs["transfer_dirs"])
        return Result("pass", "ok")

    a.gate = gate
    a._check_gate(a.cfg["rafts"][0])
    assert scopes == [[str(paths[0]) + suffix for suffix in
                       ("", "-wal", "-shm", "-journal")]]


def test_divergence_stages_and_keeps_receiver_backup(tmp_path):
    a, b, paths, shared = pair(tmp_path)
    initial_handoff(a, b)
    add(paths[0], "A kept working")
    add(paths[1], "B kept working")
    with b.locked():
        b.send()
    before = paths[0].read_bytes()
    with a.locked():
        result = a.pickup()
    assert any(r["reason"] == "diverged-or-unpaired" for r in result)
    assert paths[0].read_bytes() == before
    state = a._state("chat-state")
    backup = a.root / "backups" / state["diverged_backup"]
    assert "A kept working" in rows(backup)
    assert a.status()[0]["status"] == "diverged"


def test_sender_change_during_transfer_is_not_recorded_as_local_hash(tmp_path):
    a, b, paths, shared = pair(tmp_path)
    original = a.transport

    class MutatingTransport:
        def send(self, packet, packet_id):
            original.send(packet, packet_id)
            add(paths[0], "late edit")

    a.transport = MutatingTransport()
    with a.locked():
        assert a.send()[0]["status"] == "held"
        assert a._state("chat-state")["local_hash"] is None
    a.transport = original
    with b.locked():
        b.pickup()
        b.adopt("chat-state", keep_both=True)
    add(paths[1], "from B")
    with b.locked():
        b.send()
    with a.locked():
        outcome = a.pickup()
    assert any(r["reason"] == "diverged-or-unpaired" for r in outcome)
    assert "late edit" in rows(paths[0])


def test_wal_sender_waits_then_accepts_return_after_sidecar_closes(tmp_path):
    a, b, paths, shared = pair(tmp_path)
    live = sqlite3.connect(paths[0])
    try:
        live.execute("PRAGMA journal_mode=WAL")
        live.execute("PRAGMA wal_autocheckpoint=0")
        live.execute("INSERT INTO chat VALUES ('from WAL')")
        live.commit()
        assert Path(str(paths[0]) + "-wal").exists()
        with a.locked():
            assert a.send()[0]["status"] == "sent"
        with b.locked():
            assert b.pickup()[0]["status"] == "staged"
            b.adopt("chat-state", keep_both=True)
        assert "from WAL" in rows(paths[1])
        add(paths[1], "reply")
        with b.locked():
            assert b.send()[0]["status"] == "sent"
        with a.locked():
            result = a.pickup()
        assert any(r["reason"] == "receiver-sidecar-present" for r in result)
        assert "reply" not in rows(paths[0])
    finally:
        live.close()
    assert not Path(str(paths[0]) + "-wal").exists(), [
        (suffix, Path(str(paths[0]) + suffix).stat().st_size)
        for suffix in ("-wal", "-shm") if Path(str(paths[0]) + suffix).exists()]
    with a.locked():
        result = a.pickup()
    assert any(r["status"] == "adopted" for r in result), result
    assert rows(paths[0]) == ["base", "from WAL", "reply"]
