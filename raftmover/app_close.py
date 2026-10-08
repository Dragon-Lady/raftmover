"""Opt-in Linux polite close. Uncertainty leaves the app running."""
from dataclasses import dataclass
import os
import signal
import stat
import time

from .safety import SafetyError, sidecar_stat, source_stat


class CloseError(Exception):
    """Static reason code; never include process arguments or database paths."""


@dataclass(frozen=True)
class Process:
    pid: int
    parent: int
    uid: int
    comm: str
    cmdline: str
    exe: str
    started: int
    ticks: int


def _read_process(pid):
    path = f"/proc/{pid}"
    try:
        before = os.stat(path)
        if not stat.S_ISDIR(before.st_mode):
            raise CloseError("app-process-state-unknown")
        if before.st_uid != os.getuid():
            return None
        with open(path + "/stat", "rb") as stream:
            raw = stream.read(65537)
        if len(raw) > 65536 or b") " not in raw:
            raise CloseError("app-process-state-unknown")
        fields = raw[raw.rfind(b") ") + 2:].split()
        if len(fields) < 20 or fields[0] in {b"Z", b"X"}:
            return None
        with open(path + "/comm", "rb") as stream:
            comm = stream.read(4097)
        with open(path + "/cmdline", "rb") as stream:
            cmdline = stream.read(1048577)
        try:
            exe = os.readlink(path + "/exe")
        except OSError:
            exe = ""  # A matched owner with no readable exe cannot be closed.
        after = os.stat(path)
        if (len(comm) > 4096 or len(cmdline) > 1048576 or before.st_ino != after.st_ino
                or before.st_uid != after.st_uid):
            raise CloseError("app-process-state-unknown")
        parent, utime, stime, started = (int(fields[i]) for i in (1, 11, 12, 19))
        if not comm.strip() or started <= 0:
            raise CloseError("app-process-state-unknown")
        return Process(pid, parent, before.st_uid,
                       comm.decode("utf-8", "replace").strip(),
                       cmdline.replace(b"\0", b" ").decode("utf-8", "replace"),
                       exe.removesuffix(" (deleted)"), started, utime + stime)
    except (FileNotFoundError, ProcessLookupError):
        return None
    except (OSError, ValueError, IndexError, UnicodeError):
        raise CloseError("app-process-state-unknown") from None


def _processes():
    try:
        names = [int(entry.name) for entry in os.scandir("/proc")
                 if entry.name.isdecimal() and int(entry.name) != os.getpid()]
    except OSError:
        raise CloseError("app-process-state-unknown") from None
    found = {}
    for pid in names:
        process = _read_process(pid)
        if process is not None and process.uid == os.getuid():
            found[pid] = process
    return found


def _owner_set(processes, patterns):
    folded = tuple(pattern.casefold() for pattern in patterns)
    return {pid for pid, process in processes.items()
            if any(pattern in (process.comm + "\n" + process.cmdline).casefold()
                   for pattern in folded)}


def _family(processes, owners):
    family = set(owners)
    changed = True
    while changed:
        changed = False
        for pid, process in processes.items():
            if process.parent in family and pid not in family:
                family.add(pid)
                changed = True
    return family


def _database_signatures(rafts, window):
    values = []
    cutoff = time.time_ns() - int(window * 1_000_000_000)
    for raft in rafts:
        path = raft["path"]
        try:
            main = source_stat(path)
            wal = sidecar_stat(path.with_name(path.name + "-wal"))
            shm = sidecar_stat(path.with_name(path.name + "-shm"))
        except (OSError, SafetyError):
            raise CloseError("app-database-state-unknown") from None
        if main[3] > cutoff or (wal is not None and wal[3] > cutoff):
            raise CloseError("app-database-recently-active")
        values.append((main, wal, shm))
    return tuple(values)


def _sample(app, rafts, window):
    processes = _processes()
    owners = _owner_set(processes, app["processes"])
    if not owners:
        raise CloseError("app-process-state-unknown")
    roots = {pid for pid in owners if processes[pid].parent not in owners}
    if len(roots) != 1:
        raise CloseError("app-close-target-ambiguous")
    main = next(iter(roots))
    if (processes[main].comm.casefold() != app["processes"][0].casefold()
            or processes[main].exe != app["exe"]):
        raise CloseError("app-close-target-ambiguous")
    family = _family(processes, {main})
    if not owners <= family:
        raise CloseError("app-close-target-ambiguous")
    ancestor = os.getppid()
    seen = set()
    while ancestor in processes and ancestor not in seen:
        if ancestor in family:
            raise CloseError("app-close-own-ancestor")
        seen.add(ancestor)
        ancestor = processes[ancestor].parent
    busy = tuple(pattern.casefold() for pattern in app["busy_processes"])
    if any(any(pattern in (processes[pid].comm + "\n" + processes[pid].cmdline).casefold()
               for pattern in busy) for pid in family):
        raise CloseError("app-worker-busy")
    db = _database_signatures(rafts, window)
    return processes, owners, family, roots, db


def close_if_idle(engine, app_name, rafts, *, auto=False, user_idle=None):
    """Wait through a quiet window, then TERM only exact main comm via pidfd."""
    app = engine.cfg["apps"][app_name]
    if not rafts:
        return False
    # Ward must first identify the blocker without reading an original DB.
    for raft in rafts:
        try:
            engine._check_gate(raft)
        except Exception as exc:
            if str(exc) != "owning-app-running":
                raise CloseError("app-gate-inconclusive") from None
        else:
            return False  # Already closed: no reason to send a quit signal.
    if app.get("quit") != "signal:TERM":
        raise CloseError("owning-app-running")
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        raise CloseError("app-close-unsupported")
    window = app["app_idle_minutes"] * 60
    first, owners, family, roots, db = _sample(app, rafts, window)
    started = time.monotonic()
    time.sleep(window)
    elapsed = time.monotonic() - started
    second, owners2, family2, roots2, db2 = _sample(app, rafts, window)
    if (owners != owners2 or family != family2 or roots != roots2 or db != db2
            or any(first[pid].started != second[pid].started for pid in family)):
        raise CloseError("app-changed-during-idle-window")
    if elapsed < window * 0.95:
        raise CloseError("app-idle-window-incomplete")
    ticks = sum(max(0, second[pid].ticks - first[pid].ticks) for pid in family)
    cpu_pct = ticks / os.sysconf("SC_CLK_TCK") / elapsed * 100
    if cpu_pct > app["cpu_idle_pct"]:
        raise CloseError("app-cpu-busy")
    if auto and (user_idle is None or not user_idle()):
        raise CloseError("user-no-longer-idle")
    pidfds = []
    try:
        for pid in roots:
            fd = os.pidfd_open(pid)
            pidfds.append(fd)
            current = _read_process(pid)
            if (current is None or current.uid != os.getuid()
                    or current.started != second[pid].started
                    or current.comm.casefold() != app["processes"][0].casefold()
                    or current.exe != app["exe"]):
                raise CloseError("app-process-changed")
        for fd in pidfds:
            signal.pidfd_send_signal(fd, signal.SIGTERM)
    except OSError:
        raise CloseError("app-close-failed") from None
    finally:
        for fd in pidfds:
            os.close(fd)
    deadline = time.monotonic() + app["close_timeout_s"]
    while True:
        try:
            for raft in rafts:
                engine._check_gate(raft)
            return True
        except Exception as exc:
            if str(exc) != "owning-app-running":
                raise CloseError("app-close-gate-inconclusive") from None
        if time.monotonic() >= deadline:
            raise CloseError("app-did-not-close")
        time.sleep(min(1, max(0, deadline - time.monotonic())))
