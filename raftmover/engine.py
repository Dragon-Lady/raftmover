"""Linux SQLite handoff. Each raft proceeds independently and fails closed."""
from contextlib import contextmanager
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import sqlite3
import stat
import time
from urllib.parse import quote

from . import __version__
from .config import default_path, state_path
from .safety import (SafetyError, copy_private, digest, directory_fd, frozen_sqlite,
                     new_private_file, private_dir, remove_run, run_dir, sidecar_stat,
                     source_stat)
from .transport import TransferError, make_transport


class MoveError(Exception):
    """Static reason codes only."""


def ward_api():
    try:
        import raftward
        from raftward.api import API_VERSION, gate, verify
        match = re.match(r"^(\d+)\.(\d+)\.(\d+)(?=$|[.+-]|a\d|b\d|rc\d|dev\d|post\d)",
                         raftward.__version__)
        if match is None:
            raise ValueError
        version = tuple(int(part) for part in match.groups())
        if version < (0, 1, 4) or version >= (0, 2, 0) or API_VERSION != 1:
            raise ValueError
        return gate, verify
    except (ImportError, AttributeError, ValueError, TypeError):
        raise MoveError("raftward-unavailable") from None


def _json_read(path):
    try:
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_size > 1024 * 1024):
            raise SafetyError("unsafe-state-file")
        parent = directory_fd(path.parent)
        try:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
            try:
                data = os.read(fd, 1024 * 1024 + 1)
            finally:
                os.close(fd)
        finally:
            os.close(parent)
        if len(data) > 1024 * 1024:
            raise SafetyError("state-file-too-large")
        return json.loads(data)
    except FileNotFoundError:
        return None
    except (ValueError, UnicodeError):
        raise SafetyError("invalid-state-file") from None


def _json_write(path, data):
    raw = (json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(raw) > 1024 * 1024:
        raise SafetyError("state-file-too-large")
    tmp = path.with_name(".tmp-" + secrets.token_hex(12))
    fd = new_private_file(tmp)
    try:
        view = memoryview(raw)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        if path.exists():
            _json_read(path)
        os.replace(tmp, path)
        parent = directory_fd(path.parent)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        tmp.unlink(missing_ok=True)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def _sign(value, key):
    return hmac.new(key, _canonical(value), hashlib.sha256).hexdigest()


def _manifest(value, packet_id, allowed, key, source):
    # The contents of a transport packet are untrusted until the MAC passes.
    if not isinstance(value, dict):
        raise MoveError("invalid-manifest")
    mac = value.get("mac")
    if (not isinstance(mac, str) or len(mac) != 64
            or any(c not in "0123456789abcdef" for c in mac)):
        raise MoveError("unauthenticated-packet")
    unsigned = dict(value)
    unsigned.pop("mac")
    try:
        trusted = hmac.compare_digest(mac, _sign(unsigned, key))
    except Exception:
        trusted = False
    if not trusted:
        raise MoveError("unauthenticated-packet")
    if value.get("format") != 1:
        raise MoveError("invalid-manifest")
    if value.get("id") != packet_id or value.get("raft") not in allowed:
        raise MoveError("invalid-manifest")
    if (value.get("source") not in source
            or not isinstance(value.get("source"), str) or not value["source"].isascii()
            or not value["source"].replace("-", "").replace("_", "").isalnum()
            or len(value["source"]) > 64):
        raise MoveError("invalid-manifest")
    for key in ("sha256", "parent"):
        item = value.get(key)
        if item is not None and (not isinstance(item, str) or len(item) != 64
                                 or any(c not in "0123456789abcdef" for c in item)):
            raise MoveError("invalid-manifest")
    if value.get("sha256") is None or value.get("ward") != "pass":
        raise MoveError("invalid-manifest")
    ancestors = value.get("ancestors")
    if (not isinstance(ancestors, list) or len(ancestors) > 512
            or any(not isinstance(item, str) or len(item) != 64
                   or any(c not in "0123456789abcdef" for c in item)
                   for item in ancestors)):
        raise MoveError("invalid-manifest")
    if type(value.get("size")) is not int or not 0 < value["size"] <= 100 * 1024**3:
        raise MoveError("invalid-manifest")
    if type(value.get("generation")) is not int or not 1 <= value["generation"] <= 2**63 - 1:
        raise MoveError("invalid-manifest")
    return value


class Engine:
    def __init__(self, cfg, root=None, key_path=None):
        self.cfg = cfg
        self.root = Path(root or state_path())
        self.gate, self.verify = ward_api()
        self.key = self._load_key(Path(key_path or default_path().parent / "pair.key"))
        self.transport = make_transport(cfg)
        self.results = []
        self.recovery_rows = []
        self.open_file_check = "verified"

    @staticmethod
    def _load_key(path):
        try:
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_size != 32):
                raise MoveError("unsafe-pair-key")
            parent = directory_fd(path.parent)
            try:
                fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
                try:
                    data = os.read(fd, 33)
                    if len(data) != 32 or os.fstat(fd).st_ino != info.st_ino:
                        raise MoveError("unsafe-pair-key")
                finally:
                    os.close(fd)
            finally:
                os.close(parent)
            return data
        except FileNotFoundError:
            raise MoveError("pair-key-missing") from None
        except OSError:
            raise MoveError("unsafe-pair-key") from None

    @contextmanager
    def locked(self):
        private_dir(self.root)
        for name in ("runs", "staged", "backups", "lineage", "receipts", "hashes"):
            private_dir(self.root / name)
        lock = self.root / "lock"
        try:
            fd = new_private_file(lock)
        except FileExistsError:
            parent = directory_fd(lock.parent)
            try:
                fd = os.open(lock.name, os.O_RDWR | os.O_NOFOLLOW, dir_fd=parent)
            finally:
                os.close(parent)
            info = os.fstat(fd)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
                os.close(fd)
                raise SafetyError("unsafe-lock")
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise MoveError("another-run-active") from None
            for item in (self.root / "runs").iterdir():
                if item.name.startswith("run-"):
                    remove_run(item)
            self._reconcile_pending()
            for raft in self.cfg["rafts"]:
                try:
                    self._check_gate(raft)
                    self._sweep_temp(raft)
                except (MoveError, SafetyError, OSError):
                    pass
            yield
        finally:
            os.close(fd)

    def _state(self, label):
        value = _json_read(self.root / "lineage" / (label + ".json"))
        if value is None:
            return {"last_hash": None, "status": "unpaired"}
        h = value.get("last_hash")
        if h is not None and (not isinstance(h, str) or len(h) != 64
                              or any(c not in "0123456789abcdef" for c in h)):
            raise SafetyError("invalid-lineage")
        history = value.get("history", [])
        if (not isinstance(history, list) or len(history) > 512
                or any(not isinstance(item, str) or len(item) != 64
                       or any(c not in "0123456789abcdef" for c in item)
                       for item in history)):
            raise SafetyError("invalid-lineage")
        generation = value.get("generation", 0)
        if type(generation) is not int or not 0 <= generation <= 2**63 - 1:
            raise SafetyError("invalid-lineage")
        return value

    def _sweep_temp(self, raft):
        allowed_modes = {0o600}
        try:
            allowed_modes.add(stat.S_IMODE(source_stat(raft["path"])[-1]))
        except FileNotFoundError:
            pass
        pending_temps = set()
        for receipt_path in (self.root / "receipts").glob("*.json"):
            receipt = _json_read(receipt_path)
            if isinstance(receipt, dict) and receipt.get("status") == "pending":
                name = receipt.get("temp")
                if isinstance(name, str) and re.fullmatch(r"\.raftmover-[0-9a-f]{24}", name):
                    pending_temps.add(name)
        parent = directory_fd(raft["path"].parent)
        try:
            with os.scandir(parent) as entries:
                for entry in entries:
                    if not re.fullmatch(r"\.raftmover-[0-9a-f]{24}", entry.name):
                        continue
                    if entry.name in pending_temps:
                        continue
                    info = os.stat(entry.name, dir_fd=parent, follow_symlinks=False)
                    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                            or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) not in allowed_modes):
                        continue
                    self._check_gate(raft)
                    os.unlink(entry.name, dir_fd=parent)
        finally:
            os.close(parent)

    def _save(self, label, **fields):
        state = self._state(label)
        state.update(fields)
        _json_write(self.root / "lineage" / (label + ".json"), state)

    def _raft(self, label):
        for raft in self.cfg["rafts"]:
            if raft["label"] == label:
                return raft
        raise MoveError("unknown-raft")

    def _receipt(self, packet_id):
        if not isinstance(packet_id, str) or len(packet_id) != 32 or any(
                c not in "0123456789abcdef" for c in packet_id):
            raise MoveError("invalid-packet-id")
        return self.root / "receipts" / (packet_id + ".json")

    def _consumed(self, packet_id):
        receipt = _json_read(self._receipt(packet_id))
        if receipt is None:
            return False
        if receipt.get("status") not in {"pending", "applied", "declined", "own", "retired"}:
            raise SafetyError("invalid-receipt")
        return receipt["status"] not in {"pending", "declined"}

    def _pending_for(self, label):
        pending = []
        for path in (self.root / "receipts").glob("*.json"):
            receipt = _json_read(path)
            if not isinstance(receipt, dict):
                raise SafetyError("invalid-receipt")
            if receipt.get("status") == "pending" and receipt.get("raft") == label:
                self._receipt(path.stem)
                pending.append((path, receipt))
        return pending

    def _ack_payload(self, packet_id, label, sha256, sender, receiver, status="applied"):
        if status not in {"applied", "declined"}:
            raise MoveError("invalid-ack-status")
        unsigned = {"format": 1, "id": packet_id, "raft": label,
                    "sha256": sha256, "sender": sender, "receiver": receiver,
                    "status": status}
        return {**unsigned, "mac": _sign(unsigned, self.key)}

    @staticmethod
    def _ack_matches(value, expected):
        return (isinstance(value, dict) and value.keys() == expected.keys()
                and isinstance(value.get("mac"), str)
                and re.fullmatch(r"[0-9a-f]{64}", value["mac"]) is not None
                and hmac.compare_digest(value["mac"], expected["mac"])
                and all(value[key] == expected[key] for key in expected if key != "mac"))

    def _retire_declined(self, packet_id, receipt):
        if receipt.get("status") != "declined" or not receipt.get("ack_published"):
            return
        label = receipt.get("raft")
        self._raft(label)
        remove_run(self.root / "staged" / label / packet_id)
        state = self._state(label)
        if state.get("manual_resolution") == packet_id:
            fields = {"manual_resolution": None}
            if state.get("reason") == "current-kept-after-review":
                fields.update(status="recovered", reason="", staged_reason="")
            self._save(label, **fields)

    def _publish_ack(self, packet_id):
        receipt_path = self._receipt(packet_id)
        receipt = _json_read(receipt_path)
        if (not isinstance(receipt, dict) or receipt.get("status") not in {"applied", "declined"}
                or receipt.get("source") != self.cfg["peer_label"]
                or receipt.get("ack_published")):
            return
        ack = self._ack_payload(packet_id, receipt["raft"], receipt["sha256"],
                                self.cfg["peer_label"], self.cfg["machine_label"],
                                receipt["status"])
        run = run_dir(self.root / "runs")
        try:
            _json_write(run / "ack-source.json", ack)
            try:
                self.transport.publish_ack(packet_id, run / "ack-source.json")
            except TransferError as exc:
                if str(exc) != "ack-already-exists":
                    return
            self.transport.fetch_ack(packet_id, run)
            if not self._ack_matches(_json_read(run / "ack.json"), ack):
                return
            receipt["ack_published"] = True
            _json_write(receipt_path, receipt)
            self._retire_declined(packet_id, receipt)
        except Exception:
            pass  # Adoption stays durable; an unconfirmed ack never permits pruning.
        finally:
            remove_run(run)

    def _prune_acknowledged(self):
        by_raft = {}
        for receipt_path in (self.root / "receipts").glob("*.json"):
            try:
                receipt = _json_read(receipt_path)
                if not isinstance(receipt, dict) or receipt.get("status") != "own":
                    continue
                packet_id = receipt_path.stem
                self._receipt(packet_id)
                if not receipt.get("acked"):
                    run = run_dir(self.root / "runs")
                    try:
                        self.transport.fetch_ack(packet_id, run)
                        ack = _json_read(run / "ack.json")
                        if not any(self._ack_matches(ack, self._ack_payload(
                                packet_id, receipt["raft"], receipt["sha256"],
                                self.cfg["machine_label"], self.cfg["peer_label"], status))
                                for status in ("applied", "declined")):
                            continue
                        receipt["acked"] = True
                        _json_write(receipt_path, receipt)
                    finally:
                        remove_run(run)
                when = receipt.get("generation")
                if type(when) is int and when > 0:
                    by_raft.setdefault(receipt["raft"], []).append(
                        (when, packet_id, receipt_path, receipt))
            except Exception:
                continue
        for entries in by_raft.values():
            entries.sort(reverse=True)
            for _, packet_id, receipt_path, receipt in entries[self.cfg.get("keep_last_n", 5):]:
                try:
                    self.transport.delete_packet(packet_id)
                    receipt["status"] = "retired"
                    _json_write(receipt_path, receipt)
                except (OSError, SafetyError, TransferError):
                    pass

    def _finish_adoption(self, label, manifest, receipt, *, backup_missing=False):
        prior = self._state(label)
        self._save(label, last_hash=manifest["sha256"],
                   local_hash=manifest["sha256"], status="adopted",
                   packet=manifest["id"],
                   backup=None if backup_missing else receipt.get("backup"),
                   backup_sha256=None if backup_missing else receipt.get("backup_sha256"),
                   open_file_check=self.open_file_check,
                   lineage_broken=backup_missing,
                   reason="backup-missing-manual-review" if backup_missing else "",
                   staged_reason="",
                   generation=manifest["generation"],
                   history=list(dict.fromkeys(prior.get("history", [])
                                              + manifest["ancestors"]
                                              + [manifest["sha256"]]))[-512:])
        for value in manifest["ancestors"] + [manifest["sha256"]]:
            self._mark_hash(value)
        _json_write(self._receipt(manifest["id"]),
                    {"status": "applied", "raft": label,
                     "sha256": manifest["sha256"],
                     "source": manifest["source"], "ack_published": False})
        remove_run(self.root / "staged" / label / manifest["id"])
        self._publish_ack(manifest["id"])
        stage_root = self.root / "staged" / label
        for stage in stage_root.iterdir():
            receipt = _json_read(self._receipt(stage.name))
            if isinstance(receipt, dict) and receipt.get("status") == "declined":
                remove_run(stage)
                if self._state(label).get("manual_resolution") == stage.name:
                    self._save(label, manual_resolution=None)

    def _reconcile_pending(self):
        self.recovery_rows = []
        allowed = {r["label"] for r in self.cfg["rafts"]}
        for path in (self.root / "receipts").iterdir():
            if not path.name.endswith(".json"):
                continue
            label = "packet"
            try:
                packet_id = path.name[:-5]
                receipt = _json_read(self._receipt(packet_id))
                if receipt.get("status") != "pending":
                    continue
                label = receipt.get("raft")
                if label not in allowed:
                    raise SafetyError("invalid-receipt")
                stage = self.root / "staged" / label / packet_id
                manifest_data = _json_read(stage / "manifest.json")
                if manifest_data is None:
                    raise MoveError("pending-stage-missing")
                manifest = _manifest(manifest_data, packet_id,
                                     {label}, self.key, {self.cfg["peer_label"]})
                if receipt.get("sha256") != manifest["sha256"]:
                    raise SafetyError("invalid-receipt")
                self._check_copy(stage / "snapshot.sqlite", manifest["sha256"], manifest["size"])
                if self._state(label).get("manual_resolution") == packet_id:
                    _json_write(path, {"status": "declined", "raft": label,
                                       "sha256": manifest["sha256"],
                                       "source": manifest["source"],
                                       "ack_published": False})
                    self._publish_ack(packet_id)
                    self.recovery_rows.append({"raft": label, "status": "recovered",
                                               "reason": "current-kept-after-review"})
                    continue
                backup_name = receipt.get("backup")
                backup_hash = receipt.get("backup_sha256")
                temp_name = receipt.get("temp")
                if temp_name is not None and (not isinstance(temp_name, str)
                        or not re.fullmatch(r"\.raftmover-[0-9a-f]{24}", temp_name)):
                    raise SafetyError("invalid-receipt")
                if backup_name is not None:
                    if (not isinstance(backup_name, str)
                            or backup_name != Path(backup_name).name
                            or not backup_name.startswith(label + "-")
                            or not isinstance(backup_hash, str) or len(backup_hash) != 64):
                        raise SafetyError("invalid-receipt")
                elif backup_hash is not None:
                    raise SafetyError("invalid-receipt")
                raft = self._raft(label)
                self._check_gate(raft)
                run = run_dir(self.root / "runs")
                try:
                    try:
                        frozen, snapshot = frozen_sqlite(raft["path"], run,
                                                         lambda: self._check_gate(raft))
                        current_hash, _ = self._check_copy(frozen)
                        raw_hash = snapshot["main_hash"]
                    except FileNotFoundError:
                        current_hash = raw_hash = None
                finally:
                    remove_run(run)
                backup = self.root / "backups" / backup_name if backup_name else None
                backup_missing = False
                if backup is not None:
                    try:
                        info = backup.lstat()
                    except FileNotFoundError:
                        backup_missing = True
                    else:
                        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600
                                or digest(backup) != backup_hash):
                            raise SafetyError("pending-backup-unverifiable")
                saved = self._state(label)
                temp_exists = False
                if temp_name is not None:
                    temp_path = raft["path"].with_name(temp_name)
                    try:
                        temp_info = temp_path.lstat()
                    except FileNotFoundError:
                        pass
                    else:
                        if (not stat.S_ISREG(temp_info.st_mode)
                                or temp_info.st_uid != os.getuid() or temp_info.st_nlink != 1
                                or digest(temp_path) != manifest["sha256"]):
                            raise SafetyError("pending-temp-unverifiable")
                        temp_exists = True
                if temp_exists and not ((backup_name is None and raw_hash is None)
                                        or (backup_name is not None and raw_hash == backup_hash)):
                    # The source name still exists, so the rename did not land.
                    # Preserve the edited receiver and its pre-attempt backup.
                    reason = "pending-backup-missing" if backup_missing else "diverged-or-unpaired"
                    self._save(label, backup=None if backup_missing else backup_name,
                               backup_sha256=None if backup_missing else backup_hash,
                               lineage_broken=True, status="held", reason=reason,
                               staged_reason=reason)
                    path.unlink()
                    self.recovery_rows.append({"raft": label, "status": "held",
                                               "reason": reason})
                elif not temp_exists and current_hash == manifest["sha256"]:
                    self._finish_adoption(label, manifest, receipt,
                                          backup_missing=backup_missing)
                    self.recovery_rows.append({
                        "raft": label, "status": "held" if backup_missing else "recovered",
                        "reason": "backup-missing-manual-review" if backup_missing
                                  else "applied-packet-finalized"})
                elif (saved.get("packet") == packet_id
                      and saved.get("last_hash") == manifest["sha256"]):
                    # The swap and lineage save completed, then the receiver
                    # changed before the receipt was finalized.
                    for value in manifest["ancestors"] + [manifest["sha256"]]:
                        self._mark_hash(value)
                    _json_write(path, {"status": "applied", "raft": label,
                                       "sha256": manifest["sha256"],
                                       "source": manifest["source"],
                                       "ack_published": False})
                    remove_run(stage)
                    self._publish_ack(packet_id)
                    if backup_missing:
                        self._save(label, backup=None, backup_sha256=None,
                                   lineage_broken=True, reason="pending-backup-missing")
                    self.recovery_rows.append({"raft": label, "status": "recovered",
                                               "reason": "applied-receipt-finalized"})
                elif ((backup_name is None and raw_hash is None)
                      or (backup_name is not None and raw_hash == backup_hash)):
                    # Raw bytes still match the pre-swap receiver. A logical
                    # match alone cannot distinguish a landed swap plus edits.
                    path.unlink()
                    if backup is not None and saved.get("backup") != backup_name:
                        backup.unlink(missing_ok=True)
                else:
                    reason = ("pending-backup-missing" if backup_missing
                              else "pending-swap-ambiguous")
                    self._save(label, backup=None if backup_missing else backup_name,
                               backup_sha256=None if backup_missing else backup_hash,
                               lineage_broken=True, status="held",
                               reason=reason, staged_reason=reason)
                    raise MoveError(reason)
            except Exception as exc:
                # One blocked or unverifiable raft must not stop independent
                # rafts. Keep the pending receipt until it can be verified.
                reason = str(exc) if isinstance(exc, (MoveError, SafetyError)) else "runtime-error"
                self.recovery_rows.append({"raft": label,
                                           "status": "held", "reason": reason})
                continue

    def _hash_marker(self, value):
        if (not isinstance(value, str) or len(value) != 64
                or any(c not in "0123456789abcdef" for c in value)):
            raise MoveError("invalid-lineage-hash")
        return self.root / "hashes" / value

    def _known_hash(self, value):
        path = self._hash_marker(value)
        try:
            info = path.lstat()
        except FileNotFoundError:
            return False
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_size != 0):
            raise SafetyError("unsafe-lineage-marker")
        return True

    def _mark_hash(self, value):
        if self._known_hash(value):
            return
        try:
            os.close(new_private_file(self._hash_marker(value)))
        except FileExistsError:
            if not self._known_hash(value):
                raise SafetyError("unsafe-lineage-marker") from None

    def _check_gate(self, raft):
        patterns = self.cfg["apps"][raft["app"]]["processes"]
        result = self.gate(raft["path"], patterns,
                           transfer_dirs=[str(raft["path"])
                                          + suffix for suffix in ("", "-wal", "-shm", "-journal")])
        if getattr(result, "open_file_check", "verified") == "unverifiable":
            self.open_file_check = "unverifiable"
        if not getattr(result, "passed", False):
            raise MoveError(result.reason if result.reason in {
                "owning-app-running", "target-handle-open", "transfer-running",
                "transfer-directory-in-use", "transfer-lock-present"} else "ward-gate-inconclusive")

    def _check_copy(self, path, expected=None, size=None):
        h = expected or digest(path)
        result = self.verify(path, expected_sha256=h, expected_size=size,
                             runtime=self.root / "runs" / "ward")
        if not getattr(result, "passed", False):
            raise MoveError("ward-verify-" + ("failed" if getattr(result, "status", "") == "fail" else "inconclusive"))
        return h, result

    def send_one(self, raft):
        label = raft["label"]
        if self._pending_for(label):
            return {"raft": label, "status": "held",
                    "reason": self._state(label).get("reason")
                              or "pending-adoption-recovery-required"}
        run = run_dir(self.root / "runs")
        try:
            self._check_gate(raft)  # before any source stat, read or sidecar check
            frozen, snapshot = frozen_sqlite(raft["path"], run,
                                             lambda: self._check_gate(raft))
            h, ward = self._check_copy(frozen)
            self._check_gate(raft)
            if h == self._state(label)["last_hash"]:
                previous = self._state(label)
                if (previous.get("status") == "held"
                        and previous.get("reason") in {
                            "owning-app-running", "sent-source-state-unverified"}):
                    self._save(label, status="unchanged", reason="", staged_reason="")
                return {"raft": label, "status": "unchanged", "reason": "already-sent"}
            with sqlite3.connect("file:" + quote(str(frozen), safe="/") + "?mode=ro", uri=True) as conn:
                user_version = conn.execute("PRAGMA user_version").fetchone()[0]
            current_state = self._state(label)
            parent = None if current_state.get("lineage_broken") else current_state["last_hash"]
            generation = current_state.get("generation", 0) + 1
            packet_id = secrets.token_hex(16)
            manifest = {"format": 1, "id": packet_id, "raft": label,
                        "source": self.cfg["machine_label"], "time": int(time.time()),
                        "version": __version__, "parent": parent, "sha256": h,
                        "generation": generation,
                        "ancestors": current_state.get("history", [])[-511:],
                        "size": frozen.stat().st_size, "user_version": user_version,
                        "page_count": ward.page_count, "ward": "pass"}
            manifest["mac"] = _sign(manifest, self.key)
            _json_write(run / "manifest.json", manifest)
            self._check_gate(raft)
            self.transport.send(run, packet_id)
            # The verified packet is now visible to the receiver. Record its
            # lineage even if the app opens or edits its original afterward;
            # otherwise a later send would create an unselectable sibling.
            self._mark_hash(h)
            self._save(label, last_hash=h, local_hash=None,
                       status="sent", packet=packet_id, reason="", staged_reason="",
                       open_file_check=self.open_file_check,
                       generation=generation,
                       history=list(dict.fromkeys(current_state.get("history", []) + [h]))[-512:])
            _json_write(self._receipt(packet_id),
                        {"status": "own", "raft": label, "sha256": h,
                         "time": manifest["time"], "generation": generation,
                         "acked": False})
            try:
                # Never bless a later write as the bytes that were sent.
                self._check_gate(raft)
                same = (source_stat(raft["path"]) == snapshot["main_signature"]
                    and sidecar_stat(raft["path"].with_name(raft["path"].name + "-wal")) == snapshot["wal_signature"]
                    and sidecar_stat(raft["path"].with_name(raft["path"].name + "-shm")) == snapshot["shm_signature"])
                self._check_gate(raft)
            except (MoveError, SafetyError, OSError):
                same = False
            local_hash = (snapshot["main_hash"] if same
                          and snapshot["wal_signature"] is None
                          and snapshot["shm_signature"] is None else None)
            self._save(label, local_hash=local_hash,
                       status="sent" if same else "held",
                       reason="" if same else "sent-source-state-unverified")
            return {"raft": label, "status": "sent" if same else "held",
                    "reason": "ok" if same else "sent-source-state-unverified"}
        finally:
            remove_run(run)

    def send(self, hold_labels=None):
        rows = []
        hold_labels = hold_labels or {}
        for raft in self.cfg["rafts"]:
            if raft["label"] in hold_labels:
                reason = hold_labels[raft["label"]]
                rows.append({"raft": raft["label"], "status": "held", "reason": reason})
                self._save(raft["label"], status="held", reason=reason)
                continue
            try:
                rows.append(self.send_one(raft))
            except Exception as exc:
                reason = str(exc) if isinstance(exc, (MoveError, SafetyError, TransferError)) else "runtime-error"
                rows.append({"raft": raft["label"], "status": "held", "reason": reason})
                self._save(raft["label"], status="held", reason=reason)
        return rows

    def pickup(self, stage_only=False, hold_labels=None):
        rows = list(self.recovery_rows)
        hold_labels = hold_labels or {}
        allowed = {r["label"] for r in self.cfg["rafts"]}
        try:
            packet_ids = self.transport.packet_ids()
        except (TransferError, OSError) as exc:
            packet_ids = []
            reason = str(exc) if isinstance(exc, TransferError) else "transport-failed"
            rows.append({"raft": "packet", "status": "held", "reason": reason})
        rows.extend(getattr(self.transport, "held_packets", []))
        for packet_id in packet_ids:
            try:
                if self._consumed(packet_id):
                    receipt = _json_read(self._receipt(packet_id))
                    if receipt.get("status") in {"applied", "declined"} and not receipt.get("ack_published"):
                        self._publish_ack(packet_id)
                    continue
                receipt = _json_read(self._receipt(packet_id))
                if isinstance(receipt, dict) and receipt.get("status") == "declined":
                    if not receipt.get("ack_published"):
                        self._publish_ack(packet_id)
                    elif receipt.get("raft") in allowed:
                        self._retire_declined(packet_id, receipt)
                    continue
            except Exception:
                rows.append({"raft": "packet", "status": "held", "reason": "receipt-state-unverifiable"})
                continue
            run = run_dir(self.root / "runs")
            try:
                self.transport.fetch_manifest(packet_id, run)
                manifest = _manifest(_json_read(run / "manifest.json"), packet_id,
                                     allowed, self.key,
                                     {self.cfg["peer_label"], self.cfg["machine_label"]})
                if manifest["source"] == self.cfg["machine_label"]:
                    _json_write(self._receipt(packet_id),
                                {"status": "own", "raft": manifest["raft"],
                                 "sha256": manifest["sha256"],
                                 "time": manifest["time"],
                                 "generation": manifest["generation"], "acked": False})
                    continue
                label = manifest["raft"]
                state = self._state(label)
                if (manifest["sha256"] == state["last_hash"]
                        or manifest["sha256"] in state.get("history", [])
                        or self._known_hash(manifest["sha256"])):
                    _json_write(self._receipt(packet_id),
                                {"status": "applied", "raft": label,
                                 "sha256": manifest["sha256"],
                                 "source": manifest["source"],
                                 "ack_published": False})
                    self._publish_ack(packet_id)
                    continue
                stage_root = self.root / "staged" / label
                private_dir(stage_root)
                stage = stage_root / packet_id
                if stage.exists():
                    continue
                self.transport.fetch_snapshot(packet_id, run)
                self._check_copy(run / "snapshot.sqlite", manifest["sha256"], manifest["size"])
                os.replace(run, stage)
                run = None
            except Exception as exc:
                reason = str(exc) if isinstance(exc, (MoveError, SafetyError, TransferError)) else "runtime-error"
                rows.append({"raft": "packet", "status": "held", "reason": reason})
            finally:
                if run is not None:
                    remove_run(run)
        for raft in self.cfg["rafts"]:
            label = raft["label"]
            stage_root = self.root / "staged" / label
            if not stage_root.exists():
                continue
            candidates = []
            for stage in stage_root.iterdir():
                try:
                    receipt = _json_read(self._receipt(stage.name))
                    if isinstance(receipt, dict) and receipt.get("status") == "declined":
                        if receipt.get("ack_published"):
                            self._retire_declined(stage.name, receipt)
                        else:
                            self._publish_ack(stage.name)
                            if _json_read(self._receipt(stage.name)).get("ack_published"):
                                self._retire_declined(stage.name,
                                                     _json_read(self._receipt(stage.name)))
                            else:
                                rows.append({"raft": label, "status": "staged",
                                             "reason": "declined-ack-pending"})
                        continue
                    if self._consumed(stage.name):
                        remove_run(stage)
                        continue
                    _, manifest = self._staged(label, stage.name)
                    state = self._state(label)
                    if (manifest["sha256"] == state["last_hash"]
                            or manifest["sha256"] in state.get("history", [])
                            or self._known_hash(manifest["sha256"])):
                        _json_write(self._receipt(manifest["id"]),
                                    {"status": "applied", "raft": label,
                                     "sha256": manifest["sha256"],
                                     "source": manifest["source"],
                                     "ack_published": False})
                        self._publish_ack(manifest["id"])
                        remove_run(stage)
                        continue
                    candidates.append(manifest)
                except Exception as exc:
                    reason = str(exc) if isinstance(exc, (MoveError, SafetyError)) else "runtime-error"
                    rows.append({"raft": label, "status": "held", "reason": reason})
            if stage_only or self.cfg["stage_only"] or label in hold_labels:
                reason = hold_labels.get(label, "stage-only")
                rows.extend({"raft": label, "status": "staged", "reason": reason}
                            for _ in candidates)
                if candidates:
                    self._save(label, staged_reason=reason)
                continue
            while candidates:
                state = self._state(label)
                if state.get("lineage_broken"):
                    break
                parent = state["last_hash"]
                matching = [m for m in candidates if m["parent"] == parent]
                if parent is None or len(matching) != 1:
                    break
                manifest = matching[0]
                try:
                    rows.append(self.adopt(label, manifest["id"]))
                    candidates.remove(manifest)
                except Exception as exc:
                    reason = str(exc) if isinstance(exc, (MoveError, SafetyError)) else "runtime-error"
                    rows.append({"raft": label, "status": "staged", "reason": reason})
                    self._save(label, staged_reason=reason)
                    candidates.remove(manifest)
                    break
            for manifest in candidates:
                rows.append({"raft": label, "status": "staged", "reason": "diverged-or-unpaired"})
            if candidates:
                self._save(label, staged_reason="diverged-or-unpaired")
        try:
            self._prune_acknowledged()
        except Exception:
            rows.append({"raft": "packet", "status": "held", "reason": "ack-state-unverifiable"})
        return rows

    def _staged(self, label, packet_id=None):
        stage_root = self.root / "staged" / label
        if packet_id is None:
            ids = [p.name for p in stage_root.iterdir()
                   if p.is_dir() and (_json_read(self._receipt(p.name)) or {}).get("status") != "declined"] \
                  if stage_root.exists() else []
            if len(ids) != 1:
                raise MoveError("staged-packet-ambiguous" if ids else "no-staged-packet")
            packet_id = ids[0]
        stage = stage_root / packet_id
        receipt = _json_read(self._receipt(packet_id))
        if receipt is not None and receipt.get("status") == "pending":
            raise MoveError("pending-adoption-recovery-required")
        if self._consumed(packet_id):
            raise MoveError("packet-already-applied")
        if not stage.is_dir():
            raise MoveError("no-staged-packet")
        manifest = _manifest(_json_read(stage / "manifest.json"), packet_id,
                             {label}, self.key, {self.cfg["peer_label"]})
        self._check_copy(stage / "snapshot.sqlite", manifest["sha256"], manifest["size"])
        return stage, manifest

    def _preserve_diverged(self, label, frozen, current_hash):
        if frozen is None or current_hash is None:
            return
        state = self._state(label)
        old_name = state.get("diverged_backup")
        if (state.get("diverged_sha256") == current_hash
                and isinstance(old_name, str) and old_name == Path(old_name).name):
            existing = self.root / "backups" / old_name
            if existing.exists() and digest(existing) == current_hash:
                return
        name = label + "-diverged-" + str(int(time.time())) + "-" + secrets.token_hex(8) + ".sqlite"
        backup = self.root / "backups" / name
        copy_private(frozen, backup)
        if digest(backup) != current_hash:
            backup.unlink(missing_ok=True)
            raise MoveError("diverged-backup-changed")
        self._save(label, diverged_backup=name, diverged_sha256=current_hash,
                   staged_reason="diverged-or-unpaired")

    def adopt(self, label, packet_id=None, keep_both=False):
        raft = self._raft(label)
        stage, manifest = self._staged(label, packet_id)
        prior = self._state(label)
        if (manifest["sha256"] == prior["last_hash"]
                or manifest["sha256"] in prior.get("history", [])
                or self._known_hash(manifest["sha256"])):
            raise MoveError("packet-already-applied")
        if manifest["generation"] < prior.get("generation", 0):
            raise MoveError("stale-packet-generation")
        self._check_gate(raft)  # before reading or statting receiver original
        original = raft["path"]
        receiver_run = run_dir(self.root / "runs")
        local_frozen = None
        try:
            try:
                before = source_stat(original)
                local_frozen, local_snapshot = frozen_sqlite(
                    original, receiver_run, lambda: self._check_gate(raft))
                local_hash, _ = self._check_copy(local_frozen)
            except FileNotFoundError:
                before, local_hash, local_snapshot = None, None, None
            state = self._state(label)
            if (manifest["parent"] != state["last_hash"]
                    or local_hash != state["last_hash"]) and not keep_both:
                self._preserve_diverged(label, local_frozen, local_hash)
                raise MoveError("diverged-or-unpaired")
        finally:
            remove_run(receiver_run)
        if manifest["parent"] is None and not keep_both:
            raise MoveError("first-pair-needs-review")
        if local_snapshot is not None and (local_snapshot["wal_signature"] is not None
                                           or local_snapshot["shm_signature"] is not None):
            raise MoveError("receiver-sidecar-present")
        self._check_gate(raft)
        backup = None
        if before is not None:
            suffix = "-diverged-" + str(int(time.time())) if keep_both else ""
            backup = self.root / "backups" / (label + suffix + "-" + secrets.token_hex(8) + ".sqlite")
            copy_private(original, backup)
            if digest(backup) != local_snapshot["main_hash"] or source_stat(original) != before:
                backup.unlink(missing_ok=True)
                raise MoveError("receiver-changed")
        temp = original.with_name(".raftmover-" + secrets.token_hex(12))
        pending_written = False
        try:
            copy_private(stage / "snapshot.sqlite", temp)
            if digest(temp) != manifest["sha256"]:
                raise MoveError("adopt-copy-changed")
            if before is not None:
                os.chmod(temp, stat.S_IMODE(before[-1]))
            self._check_gate(raft)
            if before is not None and source_stat(original) != before:
                raise MoveError("receiver-changed")
            for suffix in ("-wal", "-shm", "-journal"):
                if sidecar_stat(original.with_name(original.name + suffix)) is not None:
                    raise MoveError("receiver-sidecar-present")
            parent = directory_fd(original.parent)
            receipt_path = self._receipt(manifest["id"])
            pending = {"status": "pending", "raft": label,
                       "sha256": manifest["sha256"],
                       "temp": temp.name,
                       "backup": backup.name if backup else None,
                       "backup_sha256": local_snapshot["main_hash"] if backup else None}
            try:
                # Keep this temp if the receipt exists but the swap is
                # interrupted. Recovery uses its digest to prove no rename
                # occurred, even if the receiver is edited meanwhile.
                pending_written = True
                _json_write(receipt_path, pending)
                os.replace(temp.name, original.name, src_dir_fd=parent, dst_dir_fd=parent)
                os.fsync(parent)
            finally:
                os.close(parent)
            self._finish_adoption(label, manifest, pending)
            return {"raft": label, "status": "adopted", "reason": "ok"}
        finally:
            if not pending_written:
                temp.unlink(missing_ok=True)

    def restore(self, label):
        raft = self._raft(label)
        state = self._state(label)
        name = state.get("backup")
        if not isinstance(name, str) or name != Path(name).name or not name.startswith(label + "-"):
            raise MoveError("no-backup")
        backup = self.root / "backups" / name
        expected = state.get("backup_sha256")
        if not isinstance(expected, str) or len(expected) != 64:
            raise MoveError("backup-hash-missing")
        if not backup.exists():
            raise MoveError("backup-missing")
        if digest(backup) != expected:
            raise MoveError("backup-hash-mismatch")
        self._check_copy(backup, expected)
        self._check_gate(raft)
        current = raft["path"]
        for suffix in ("-wal", "-shm", "-journal"):
            if sidecar_stat(current.with_name(current.name + suffix)) is not None:
                raise MoveError("receiver-sidecar-present")
        before = source_stat(current)
        current_backup = self.root / "backups" / (label + "-pre-restore-" + secrets.token_hex(8) + ".sqlite")
        copy_private(current, current_backup)
        current_hash = digest(current_backup)
        temp = current.with_name(".raftmover-" + secrets.token_hex(12))
        try:
            copy_private(backup, temp)
            os.chmod(temp, stat.S_IMODE(before[-1]))
            if source_stat(current) != before:
                raise MoveError("receiver-changed")
            self._check_gate(raft)
            for suffix in ("-wal", "-shm", "-journal"):
                if sidecar_stat(current.with_name(current.name + suffix)) is not None:
                    raise MoveError("receiver-sidecar-present")
            parent = directory_fd(current.parent)
            try:
                os.replace(temp.name, current.name, src_dir_fd=parent, dst_dir_fd=parent)
                os.fsync(parent)
            finally:
                os.close(parent)
            self._save(label, local_hash=digest(current), status="restored",
                       lineage_broken=True, backup=current_backup.name,
                       backup_sha256=current_hash,
                       open_file_check=self.open_file_check,
                       reason="", staged_reason="")
            return {"raft": label, "status": "restored", "reason": "ok"}
        finally:
            temp.unlink(missing_ok=True)

    def recover_accept_current(self, label):
        """Keep a reviewed receiver after an ambiguous swap, without adopting."""
        raft = self._raft(label)
        pending = self._pending_for(label)
        if len(pending) != 1:
            if not pending:
                state = self._state(label)
                if ((state.get("manual_resolution")
                     and state.get("reason") == "current-kept-after-review")
                        or state.get("status") == "recovered"):
                    return {"raft": label, "status": "recovered",
                            "reason": "current-already-kept"}
            raise MoveError("pending-packet-ambiguous" if pending else "no-pending-packet")
        receipt_path, receipt = pending[0]
        packet_id = receipt_path.stem
        stage = self.root / "staged" / label / packet_id
        manifest = _manifest(_json_read(stage / "manifest.json"), packet_id,
                             {label}, self.key, {self.cfg["peer_label"]})
        if receipt.get("sha256") != manifest["sha256"]:
            raise SafetyError("invalid-receipt")
        self._check_copy(stage / "snapshot.sqlite", manifest["sha256"], manifest["size"])
        self._check_gate(raft)
        original = raft["path"]
        before = source_stat(original)
        for suffix in ("-wal", "-shm", "-journal"):
            if sidecar_stat(original.with_name(original.name + suffix)) is not None:
                raise MoveError("receiver-sidecar-present")
        run = run_dir(self.root / "runs")
        try:
            frozen, snapshot = frozen_sqlite(original, run, lambda: self._check_gate(raft))
            local_hash, _ = self._check_copy(frozen)
            backup = self.root / "backups" / (label + "-accepted-current-"
                                                + secrets.token_hex(8) + ".sqlite")
            copy_private(original, backup)
            if (digest(backup) != snapshot["main_hash"]
                    or source_stat(original) != before):
                backup.unlink(missing_ok=True)
                raise MoveError("receiver-changed")
            self._check_gate(raft)
            self._save(label, local_hash=local_hash, lineage_broken=True,
                       backup=backup.name, backup_sha256=snapshot["main_hash"],
                       manual_resolution=packet_id, status="held",
                       reason="current-kept-after-review",
                       staged_reason="diverged-or-unpaired",
                       open_file_check=self.open_file_check)
            _json_write(receipt_path, {"status": "declined", "raft": label,
                                       "sha256": manifest["sha256"],
                                       "source": manifest["source"],
                                       "ack_published": False})
            self._publish_ack(packet_id)
            return {"raft": label, "status": "recovered",
                    "reason": "current-kept-after-review"}
        finally:
            remove_run(run)

    def status(self):
        rows = []
        pending = set()
        backups = {raft["label"]: {"count": 0, "bytes": 0} for raft in self.cfg["rafts"]}
        backup_dir = self.root / "backups"
        if backup_dir.exists():
            for path in backup_dir.iterdir():
                for label in sorted(backups, key=len, reverse=True):
                    if path.name.startswith(label + "-"):
                        totals = backups[label]
                        info = path.lstat()
                        if (stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                                and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600):
                            totals["count"] += 1
                            totals["bytes"] += info.st_size
                        break
        receipts = self.root / "receipts"
        if receipts.exists():
            for path in receipts.iterdir():
                if path.name.endswith(".json"):
                    receipt = _json_read(path)
                    if isinstance(receipt, dict) and receipt.get("status") == "pending":
                        pending.add(receipt.get("raft"))
        for raft in self.cfg["rafts"]:
            label = raft["label"]
            state = self._state(label)
            staged = self.root / "staged" / label
            count, invalid_stage = 0, False
            if staged.exists():
                for path in staged.iterdir():
                    try:
                        if not stat.S_ISDIR(path.lstat().st_mode):
                            invalid_stage = True
                        elif not self._consumed(path.name):
                            receipt = _json_read(self._receipt(path.name))
                            if isinstance(receipt, dict) and receipt.get("status") == "declined" \
                                    and receipt.get("ack_published"):
                                continue
                            count += 1
                    except (OSError, MoveError, SafetyError):
                        invalid_stage = True
            rows.append({"raft": label, "status": state.get("status", "unpaired"),
                         "staged": count,
                         "backup_count": backups[label]["count"],
                         "backup_bytes": backups[label]["bytes"],
                         "reason": state.get("staged_reason", "") if count else state.get("reason", ""),
                         "open_file_check": state.get("open_file_check", "not-checked")})
            if invalid_stage:
                rows[-1]["status"] = "held"
                rows[-1]["reason"] = "invalid-receipt"
            elif label in pending:
                rows[-1]["status"] = "pending"
                rows[-1]["reason"] = (state.get("reason") or state.get("staged_reason")
                                       or "pending-adoption-recovery-required")
            elif count:
                rows[-1]["status"] = "diverged" if rows[-1]["reason"] == "diverged-or-unpaired" else "staged"
        return rows
