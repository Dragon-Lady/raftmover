"""Private file operations. Errors contain reason codes, never source paths."""
import errno
import hashlib
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import tempfile
from urllib.parse import quote


class SafetyError(Exception):
    pass


CHUNK = 1024 * 1024
CHECK_EVERY = 8 * CHUNK


def directory_fd(path):
    path = Path(os.path.abspath(path))
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def private_dir(path):
    path = Path(os.path.abspath(path))
    if not path.exists():
        if not path.parent.exists():
            private_dir(path.parent)
        parent = directory_fd(path.parent)
        try:
            try:
                os.mkdir(path.name, 0o700, dir_fd=parent)
            except FileExistsError:
                pass
        finally:
            os.close(parent)
    fd = directory_fd(path)
    try:
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise SafetyError("unsafe-private-directory")
    finally:
        os.close(fd)


def new_private_file(path):
    parent = directory_fd(Path(path).parent)
    try:
        fd = os.open(Path(path).name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW, 0o600, dir_fd=parent)
        if stat.S_IMODE(os.fstat(fd).st_mode) != 0o600:
            os.close(fd)
            raise SafetyError("unsafe-private-file")
        return fd
    finally:
        os.close(parent)


def digest(path):
    h = hashlib.sha256()
    parent = directory_fd(Path(path).parent)
    try:
        fd = os.open(Path(path).name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=parent)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise SafetyError("unsafe-file")
            while data := os.read(fd, CHUNK):
                h.update(data)
            after = os.fstat(fd)
            if signature(before) != signature(after):
                raise SafetyError("file-changed")
        finally:
            os.close(fd)
    finally:
        os.close(parent)
    return h.hexdigest()


def signature(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_mode)


def source_stat(path):
    parent = directory_fd(Path(path).parent)
    try:
        info = os.stat(Path(path).name, dir_fd=parent, follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
            raise SafetyError("unsafe-source")
        return signature(info)
    finally:
        os.close(parent)


def sidecar_stat(path):
    try:
        return source_stat(path)
    except FileNotFoundError:
        return None


def _copy_one(source, output, gate):
    parent = directory_fd(source.parent)
    fd = None
    try:
        flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NOATIME", 0)
        try:
            fd = os.open(source.name, flags, dir_fd=parent)
        except OSError as exc:
            if exc.errno not in (errno.EPERM, errno.EACCES):
                raise
            fd = os.open(source.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or before.st_nlink != 1:
            raise SafetyError("unsafe-source")
        written = 0
        hash_value = hashlib.sha256()
        target = new_private_file(output)
        try:
            while block := os.read(fd, CHUNK):
                hash_value.update(block)
                view = memoryview(block)
                while view:
                    view = view[os.write(target, view):]
                written += len(block)
                if written % CHECK_EVERY < CHUNK:
                    gate()
            os.fsync(target)
        finally:
            os.close(target)
        if (written != before.st_size or signature(before) != signature(os.fstat(fd))
                or signature(before) != source_stat(source)):
            raise SafetyError("source-changed")
        return signature(before), hash_value.hexdigest()
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def frozen_sqlite(source, run_dir, gate):
    """Byte copy main and WAL, then checkpoint only the private copy."""
    source = Path(source)
    gate()
    before = source_stat(source)
    wal = source.with_name(source.name + "-wal")
    shm = source.with_name(source.name + "-shm")
    journal = source.with_name(source.name + "-journal")
    if sidecar_stat(journal) is not None:
        raise SafetyError("sqlite-journal-present")
    wal_before, shm_before = sidecar_stat(wal), sidecar_stat(shm)
    raw = run_dir / "raw.sqlite"
    main_signature, main_hash = _copy_one(source, raw, gate)
    if wal_before is not None:
        _copy_one(wal, run_dir / "raw.sqlite-wal", gate)
    gate()
    if (source_stat(source) != before or sidecar_stat(wal) != wal_before
            or sidecar_stat(shm) != shm_before or sidecar_stat(journal) is not None):
        raise SafetyError("source-changed")
    frozen = run_dir / "snapshot.sqlite"
    fd = new_private_file(frozen)
    os.close(fd)
    left = right = None
    try:
        left = sqlite3.connect("file:" + quote(str(raw), safe="/") + "?mode=rw", uri=True)
        left.execute("PRAGMA trusted_schema=OFF")
        right = sqlite3.connect(str(frozen))
        left.backup(right, pages=128, progress=lambda *_: gate())
        right.close()
        right = None
        left.close()
        left = None
    except sqlite3.Error:
        raise SafetyError("sqlite-backup-failed") from None
    finally:
        if right is not None:
            right.close()
        if left is not None:
            left.close()
    gate()
    if (source_stat(source) != before or sidecar_stat(wal) != wal_before
            or sidecar_stat(shm) != shm_before or sidecar_stat(journal) is not None):
        raise SafetyError("source-changed")
    for name in ("raw.sqlite", "raw.sqlite-wal", "raw.sqlite-shm"):
        (run_dir / name).unlink(missing_ok=True)
    return frozen, {"main_signature": main_signature, "main_hash": main_hash,
                    "wal_signature": wal_before, "shm_signature": shm_before}


def copy_private(source, destination):
    """Copy a trusted private source to a new 0600 destination."""
    fd = new_private_file(destination)
    try:
        with open(source, "rb") as inp:
            while block := inp.read(CHUNK):
                view = memoryview(block)
                while view:
                    view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)


def remove_run(path):
    if path.exists():
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise SafetyError("unsafe-stale-run")
        shutil.rmtree(path)


def run_dir(root):
    private_dir(root)
    return Path(tempfile.mkdtemp(prefix="run-", dir=root))
