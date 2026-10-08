"""Packet transports. The manifest is always the final upload."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
from datetime import datetime, timedelta, timezone

from .config import ConfigError
from .safety import SafetyError, copy_private, directory_fd, new_private_file, remove_run, signature


ID = re.compile(r"[0-9a-f]{32}\Z")


class TransferError(Exception):
    """Static messages only; never include remote paths or command output."""


def digest(path):
    value = hashlib.sha256()
    with open(path, "rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def _safe_packet_id(value):
    if not isinstance(value, str) or not ID.fullmatch(value):
        raise TransferError("invalid-packet-id")
    return value


def _command(argv, timeout=300):
    try:
        result = subprocess.run(argv, check=False, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=timeout,
                                umask=0o077)
    except (OSError, subprocess.TimeoutExpired):
        raise TransferError("transport-unavailable") from None
    if result.returncode:
        raise TransferError("transport-failed")
    return result.stdout


class Folder:
    def __init__(self, root):
        self.root = Path(root)
        self.held_packets = []

    def _incoming(self):
        try:
            root_fd = directory_fd(self.root)
            info = os.fstat(root_fd)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
                raise TransferError("unsafe-shared-folder")
            incoming = self.root / "incoming"
            try:
                os.mkdir("incoming", mode=0o700, dir_fd=root_fd)
            except FileExistsError:
                pass
            incoming_fd = os.open("incoming", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                  dir_fd=root_fd)
            info = os.fstat(incoming_fd)
            os.close(incoming_fd)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise TransferError("unsafe-shared-folder")
            return incoming
        except OSError:
            raise TransferError("shared-folder-unavailable") from None
        finally:
            if "root_fd" in locals():
                os.close(root_fd)

    def send(self, packet, packet_id):
        packet_id = _safe_packet_id(packet_id)
        incoming = self._incoming()
        partial = incoming / (".partial-" + packet_id)
        final = incoming / packet_id
        if os.path.lexists(partial) or os.path.lexists(final):
            raise TransferError("packet-id-collision")
        partial.mkdir(mode=0o700)
        try:
            copy_private(packet / "snapshot.sqlite", partial / "snapshot.sqlite")
            if digest(partial / "snapshot.sqlite") != digest(packet / "snapshot.sqlite"):
                raise TransferError("transfer-hash-mismatch")
            copy_private(packet / "manifest.json", partial / "manifest.json")
            os.replace(partial, final)
        except BaseException:
            shutil.rmtree(partial, ignore_errors=True)
            raise

    def _sweep_partials(self):
        """Leave recent uploads alone; remove only old private partial dirs."""
        incoming = self._incoming()
        cutoff = datetime.now(timezone.utc).timestamp() - 7 * 86400
        for path in incoming.iterdir():
            if not re.fullmatch(r"\.partial-[0-9a-f]{32}", path.name):
                continue
            try:
                info = path.lstat()
                if (stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
                        and stat.S_IMODE(info.st_mode) == 0o700 and info.st_mtime < cutoff):
                    remove_run(path)
            except (OSError, SafetyError):
                pass

    def _sweep_incomplete(self):
        """Retire only old private packet folders that never published a manifest."""
        incoming = self._incoming()
        cutoff = datetime.now(timezone.utc).timestamp() - 7 * 86400
        for path in incoming.iterdir():
            if not ID.fullmatch(path.name):
                continue
            try:
                info = path.lstat()
                if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                        or stat.S_IMODE(info.st_mode) != 0o700 or info.st_mtime >= cutoff
                        or (path / "manifest.json").exists()):
                    continue
                entries = list(path.iterdir())
                if len(entries) > 1 or (entries and entries[0].name != "snapshot.sqlite"):
                    continue
                if entries:
                    item = entries[0].lstat()
                    if (not stat.S_ISREG(item.st_mode) or item.st_uid != os.getuid()
                            or item.st_nlink != 1 or stat.S_IMODE(item.st_mode) != 0o600):
                        continue
                remove_run(path)
            except (OSError, SafetyError):
                pass

    def _cleanup_ack_temp(self, packet_id, *, prune=False):
        packet = self._incoming() / _safe_packet_id(packet_id)
        try:
            folder = packet.lstat()
            if (not stat.S_ISDIR(folder.st_mode) or folder.st_uid != os.getuid()
                    or stat.S_IMODE(folder.st_mode) != 0o700):
                raise TransferError("unsafe-packet-directory")
        except FileNotFoundError:
            return
        try:
            ack = (packet / "ack.json").lstat()
        except FileNotFoundError:
            ack = None
        if ack is not None and (not stat.S_ISREG(ack.st_mode) or ack.st_uid != os.getuid()
                                or stat.S_IMODE(ack.st_mode) != 0o600):
            raise TransferError("unsafe-packet-file")
        for path in packet.iterdir():
            if not re.fullmatch(r"\.ack-[0-9a-f]{16}", path.name):
                continue
            info = path.lstat()
            if (stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                    and stat.S_IMODE(info.st_mode) == 0o600
                    and ((ack is not None and info.st_ino == ack.st_ino
                          and info.st_dev == ack.st_dev) or (prune and info.st_nlink == 1))):
                path.unlink()

    def packet_ids(self):
        self.held_packets = []
        self._sweep_partials()
        self._sweep_incomplete()
        incoming = self._incoming()
        parent = directory_fd(incoming)
        try:
            with os.scandir(parent) as entries:
                ids = []
                for entry in entries:
                    if not ID.fullmatch(entry.name):
                        continue
                    try:
                        info = os.stat(entry.name, dir_fd=parent, follow_symlinks=False)
                    except OSError:
                        self.held_packets.append({"raft": "packet", "status": "held",
                                                  "reason": "unsafe-packet-directory",
                                                  "packet": entry.name})
                        continue
                    if not (stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
                            and stat.S_IMODE(info.st_mode) == 0o700):
                        self.held_packets.append({"raft": "packet", "status": "held",
                                                  "reason": "unsafe-packet-directory",
                                                  "packet": entry.name})
                        continue
                    packet_fd = os.open(entry.name,
                                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                        dir_fd=parent)
                    try:
                        try:
                            manifest = os.stat("manifest.json", dir_fd=packet_fd,
                                               follow_symlinks=False)
                        except FileNotFoundError:
                            self.held_packets.append({"raft": "packet", "status": "held",
                                                      "reason": "incomplete-packet"})
                            continue
                        if not stat.S_ISREG(manifest.st_mode):
                            self.held_packets.append({"raft": "packet", "status": "held",
                                                      "reason": "unsafe-packet-file"})
                            continue
                    finally:
                        os.close(packet_fd)
                    ids.append(entry.name)
                return sorted(ids)
        finally:
            os.close(parent)

    def _fetch_one(self, packet_id, destination, name):
        packet_id = _safe_packet_id(packet_id)
        parent = directory_fd(self._incoming())
        packet_fd = None
        try:
            packet_fd = os.open(packet_id, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=parent)
            folder_info = os.fstat(packet_fd)
            if folder_info.st_uid != os.getuid() or stat.S_IMODE(folder_info.st_mode) != 0o700:
                raise TransferError("unsafe-packet-directory")
            # A FIFO must not wait forever for a writer while holding Mover's
            # run lock. Check the opened file type before reading it.
            source_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                dir_fd=packet_fd)
            try:
                info = os.fstat(source_fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                        or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
                    raise TransferError("unsafe-packet-file")
                output = new_private_file(destination / name)
                try:
                    while block := os.read(source_fd, 1024 * 1024):
                        view = memoryview(block)
                        while view:
                            view = view[os.write(output, view):]
                    os.fsync(output)
                finally:
                    os.close(output)
                if signature(info) != signature(os.fstat(source_fd)):
                    raise TransferError("packet-changed")
            finally:
                os.close(source_fd)
        except FileNotFoundError:
            raise TransferError("incomplete-packet") from None
        except OSError:
            raise TransferError("unsafe-packet-file") from None
        finally:
            if packet_fd is not None:
                os.close(packet_fd)
            os.close(parent)

    def fetch_manifest(self, packet_id, destination):
        self._fetch_one(packet_id, destination, "manifest.json")

    def fetch_snapshot(self, packet_id, destination):
        self._fetch_one(packet_id, destination, "snapshot.sqlite")

    def fetch(self, packet_id, destination):
        self.fetch_manifest(packet_id, destination)
        self.fetch_snapshot(packet_id, destination)

    def publish_ack(self, packet_id, source):
        packet_id = _safe_packet_id(packet_id)
        packet = self._incoming() / packet_id
        info = packet.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise TransferError("unsafe-packet-directory")
        temporary = packet / (".ack-" + os.urandom(8).hex())
        try:
            copy_private(source, temporary)
            os.link(temporary, packet / "ack.json", follow_symlinks=False)
        except FileExistsError:
            raise TransferError("ack-already-exists") from None
        except OSError:
            raise TransferError("ack-publish-failed") from None
        finally:
            temporary.unlink(missing_ok=True)

    def fetch_ack(self, packet_id, destination):
        self._cleanup_ack_temp(packet_id)
        self._fetch_one(packet_id, destination, "ack.json")

    def delete_packet(self, packet_id):
        packet = self._incoming() / _safe_packet_id(packet_id)
        try:
            info = packet.lstat()
        except FileNotFoundError:
            return
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise TransferError("unsafe-packet-directory")
        self._cleanup_ack_temp(packet_id, prune=True)
        names = {p.name for p in packet.iterdir()}
        if not names <= {"snapshot.sqlite", "manifest.json", "ack.json"}:
            raise TransferError("packet-retention-unsafe")
        for path in packet.iterdir():
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
                raise TransferError("packet-retention-unsafe")
        for name in ("manifest.json", "snapshot.sqlite", "ack.json"):
            if name in names:
                (packet / name).unlink()
        packet.rmdir()


class Rclone:
    def __init__(self, remote):
        self.remote = remote.rstrip("/")
        self.held_packets = []
        self._checked_config = False

    def _preflight(self):
        if self._checked_config:
            return
        if self.remote.startswith(":local:"):
            self._checked_config = True
            return
        if self.remote.startswith(":"):
            raise TransferError("transport-config-unverifiable")
        try:
            data = json.loads(_command(["rclone", "config", "dump"], timeout=30))
            if not isinstance(data, dict):
                raise ValueError
            providers = json.loads(_command(["rclone", "config", "providers"], timeout=30))
            if not isinstance(providers, list):
                raise ValueError
            virtual = {item.get("Prefix"): item.get("Overview", {}).get("Virtual")
                       for item in providers if isinstance(item, dict)
                       and isinstance(item.get("Overview"), dict)}
            current = self.remote.split(":", 1)[0]
            seen = set()
            while current:
                if current in seen or len(seen) > 8:
                    raise ValueError
                seen.add(current)
                options = data.get(current)
                if not isinstance(options, dict):
                    raise ValueError
                kind = options.get("type")
                if not isinstance(kind, str) or kind not in virtual:
                    raise TransferError("transport-config-unverifiable")
                if kind == "sftp":
                    override = os.environ.get(
                        "RCLONE_CONFIG_" + current.upper() + "_KNOWN_HOSTS_FILE")
                    known = override if override is not None else options.get("known_hosts_file")
                    keys = options.get("host_keys")
                    if (known == "none" or (not known and not keys)):
                        raise TransferError("sftp-host-key-unverified")
                    break
                if kind not in {"crypt", "alias"}:
                    if virtual[kind] is not False:
                        raise TransferError("transport-config-unverifiable")
                    break
                nested = options.get("remote")
                if not isinstance(nested, str) or ":" not in nested:
                    raise ValueError
                if nested.startswith(":") and not nested.startswith(":local:"):
                    raise TransferError("transport-config-unverifiable")
                current = nested.split(":", 1)[0]
                if not current and nested.startswith(":local:"):
                    break
            self._checked_config = True
        except TransferError:
            raise
        except (ValueError, TypeError, KeyError, UnicodeError):
            raise TransferError("transport-config-unverifiable") from None

    def _file(self, packet_id, name):
        return f"{self.remote}/incoming/{_safe_packet_id(packet_id)}/{name}"

    def _partial(self, packet_id, name=""):
        path = f"{self.remote}/incoming/.partial-{_safe_packet_id(packet_id)}"
        return path + ("/" + name if name else "")

    def _incomplete_final(self, packet_id):
        """Remove only a final directory that has never exposed a manifest."""
        folder = f"{self.remote}/incoming/{_safe_packet_id(packet_id)}"
        names = set(_command(["rclone", "lsf", "--files-only", "--", folder])
                    .decode("utf-8", "replace").splitlines())
        if names <= {"snapshot.sqlite"}:
            _command(["rclone", "purge", "--", folder], timeout=300)

    def _sweep_partials(self, complete_ids=None):
        """Remove only old incomplete upload directories with a known modtime."""
        try:
            raw = _command(["rclone", "lsjson", "--dirs-only", "--",
                            self.remote + "/incoming"], timeout=60)
            entries = json.loads(raw)
            if not isinstance(entries, list):
                return
            cutoff = datetime.now(timezone.utc) - timedelta(days=7)
            for entry in entries:
                if not isinstance(entry, dict) or not entry.get("IsDir"):
                    continue
                name = entry.get("Name")
                stamp = entry.get("ModTime")
                if (not isinstance(name, str) or not isinstance(stamp, str)
                        or stamp.startswith("2000-01-01")):
                    continue
                try:
                    modified = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
                except ValueError:
                    continue
                if modified.tzinfo is not None and modified < cutoff:
                    if re.fullmatch(r"\.partial-[0-9a-f]{32}", name):
                        _command(["rclone", "purge", "--",
                                  self.remote + "/incoming/" + name], timeout=300)
                    elif (complete_ids is not None and ID.fullmatch(name)
                          and name not in complete_ids):
                        self._incomplete_final(name)
        except (TransferError, ValueError, TypeError):
            pass  # Cleanup failure never approves or blocks a packet.

    def send(self, packet, packet_id):
        self._preflight()
        packet_id = _safe_packet_id(packet_id)
        self._sweep_partials()
        partial_db = self._partial(packet_id, "snapshot.sqlite")
        final_db = self._file(packet_id, "snapshot.sqlite")
        size = (packet / "snapshot.sqlite").stat().st_size
        timeout = max(300, min(21600, 60 + size // (1024 * 1024)))
        verify = packet / "remote-verify.sqlite"
        manifest_written = False
        try:
            _command(["rclone", "copyto", "--immutable", "--",
                      str(packet / "snapshot.sqlite"), partial_db], timeout)
            # Download through crypt rather than trusting a backend hash.
            _command(["rclone", "copyto", "--", partial_db, str(verify)], timeout)
            if digest(verify) != digest(packet / "snapshot.sqlite"):
                raise TransferError("transfer-hash-mismatch")
            verify.unlink(missing_ok=True)
            _command(["rclone", "copyto", "--immutable", "--",
                      partial_db, final_db], timeout)
            _command(["rclone", "copyto", "--", final_db, str(verify)], timeout)
            if digest(verify) != digest(packet / "snapshot.sqlite"):
                raise TransferError("transfer-hash-mismatch")
            verify.unlink(missing_ok=True)
            # A receiver ignores a directory until its manifest arrives.
            _command(["rclone", "copyto", "--immutable", "--",
                      str(packet / "manifest.json"), self._file(packet_id, "manifest.json")])
            manifest_written = True
        finally:
            verify.unlink(missing_ok=True)
            if not manifest_written:
                try:
                    self._incomplete_final(packet_id)
                except TransferError:
                    pass
            try:
                _command(["rclone", "purge", "--", self._partial(packet_id)], timeout=300)
            except TransferError:
                pass

    def packet_ids(self):
        self._preflight()
        self.held_packets = []
        incoming = self.remote + "/incoming"
        _command(["rclone", "mkdir", "--", incoming])
        output = _command(["rclone", "lsf", "-R", "--files-only", "--", incoming])
        files = output.decode("utf-8", "replace").splitlines()
        seen = {name.split("/", 1)[0] for name in files if "/" in name
                and ID.fullmatch(name.split("/", 1)[0])}
        complete = {name.split("/", 1)[0] for name in files
                    if name.endswith("/manifest.json") and ID.fullmatch(name.split("/", 1)[0])
                    and name.count("/") == 1}
        # A manifest is the publication marker. Incomplete finals are never
        # offered to pickup and only age-qualified cleanup may remove them.
        self._sweep_partials(complete)
        self.held_packets.extend({"raft": "packet", "status": "held",
                                  "reason": "incomplete-packet"}
                                 for _ in sorted(seen - complete))
        return sorted(complete)

    def _fetch_one(self, packet_id, destination, name):
        self._preflight()
        _command(["rclone", "copyto", "--", self._file(packet_id, name), str(destination / name)],
                 21600 if name == "snapshot.sqlite" else 300)
        os.chmod(destination / name, 0o600)

    def fetch_manifest(self, packet_id, destination):
        self._preflight()
        folder = f"{self.remote}/incoming/{_safe_packet_id(packet_id)}"
        names = set(_command(["rclone", "lsf", "--files-only", "--", folder])
                    .decode("utf-8", "replace").splitlines())
        if "manifest.json" not in names:
            raise TransferError("incomplete-packet")
        self._fetch_one(packet_id, destination, "manifest.json")

    def fetch_snapshot(self, packet_id, destination):
        self._fetch_one(packet_id, destination, "snapshot.sqlite")

    def fetch(self, packet_id, destination):
        self.fetch_manifest(packet_id, destination)
        self.fetch_snapshot(packet_id, destination)

    def publish_ack(self, packet_id, source):
        self._preflight()
        _command(["rclone", "copyto", "--immutable", "--", str(source),
                  self._file(packet_id, "ack.json")])

    def fetch_ack(self, packet_id, destination):
        self._fetch_one(packet_id, destination, "ack.json")

    def delete_packet(self, packet_id):
        self._preflight()
        packet_id = _safe_packet_id(packet_id)
        folder = f"{self.remote}/incoming/{packet_id}"
        output = _command(["rclone", "lsf", "--files-only", "--", folder])
        names = set(output.decode("utf-8", "replace").splitlines())
        if not names <= {"snapshot.sqlite", "manifest.json", "ack.json"}:
            raise TransferError("packet-retention-unsafe")
        for name in ("manifest.json", "snapshot.sqlite", "ack.json"):
            if name in names:
                _command(["rclone", "deletefile", "--", folder + "/" + name])
        _command(["rclone", "rmdir", "--", folder])


def make_transport(cfg):
    options = cfg["transport"]
    if options["kind"] == "folder":
        return Folder(options["path"])
    if options["kind"] == "rclone":
        return Rclone(options["remote"])
    raise ConfigError("rsync transport is not yet implemented")
