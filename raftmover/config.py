"""Strict, explicit configuration. No path discovery or command shell."""
import os
from pathlib import Path
import re
import stat
import sys
try:
    import tomllib
except ImportError:
    import tomli as tomllib


LABEL = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
REMOTE = re.compile(r"[A-Za-z0-9_.@:/~+-]{1,240}\Z")
# Raft Ward owner exemptions Mover may pass. Each is a fixed structural check in
# Raft Ward; an exempt process still blocks on open target files and transfers.
OWNER_EXEMPT_KINDS = ("cursor-agent-worker",)
DEFAULT_OWNER_EXEMPT = ("cursor-agent-worker",)


class ConfigError(Exception):
    """Static messages only: no private paths or contents in errors."""


def default_path():
    root = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return root / "raftmover" / "config.toml"


def state_path():
    root = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state"))
    return root / "raftmover"


def runtime_path():
    root = os.environ.get("XDG_RUNTIME_DIR")
    if not root:
        raise ConfigError("private runtime directory unavailable")
    return Path(root) / "raftmover"


def _path(text):
    if not isinstance(text, str) or not text or "\x00" in text or any(x in text for x in "*?[]"):
        raise ConfigError("path must be an explicit file or directory")
    return Path(os.path.abspath(os.path.expanduser(text)))


def _name(value):
    return isinstance(value, str) and bool(LABEL.fullmatch(value))


def _patterns(value):
    return (isinstance(value, list) and bool(value)
            and all(isinstance(p, str) and p and "\x00" not in p for p in value))


def validate(raw):
    if sys.platform != "linux":
        raise ConfigError("Raft Mover v0.1 requires Linux Raft Ward process gating")
    if not isinstance(raw, dict):
        raise ConfigError("configuration must be a table")
    label = raw.get("machine_label")
    if not _name(label):
        raise ConfigError("machine_label must be a simple unique name")
    peer = raw.get("peer_label")
    if not _name(peer) or peer == label:
        raise ConfigError("peer_label must name the other machine")
    transport = raw.get("transport")
    if not isinstance(transport, dict) or transport.get("kind") not in {"folder", "rclone"}:
        raise ConfigError("transport must be folder or rclone; rsync is not implemented")
    kind = transport["kind"]
    if kind == "folder":
        transport = {"kind": kind, "path": _path(transport.get("path"))}
    else:
        key = "remote"
        value = transport.get(key)
        if (not isinstance(value, str) or not REMOTE.fullmatch(value) or ":" not in value
                or ".." in value or value.startswith("-")):
            raise ConfigError("invalid transport destination")
        transport = {"kind": kind, key: value}
    apps = raw.get("apps")
    if not isinstance(apps, dict) or not apps:
        raise ConfigError("at least one app must be configured")
    checked_apps = {}
    for name, app in apps.items():
        if not _name(name) or not isinstance(app, dict) or not _patterns(app.get("processes")):
            raise ConfigError("apps require simple names and process patterns")
        checked_apps[name] = {"processes": app["processes"]}
        if any(key in app for key in ("quit", "exe", "close_timeout_s", "cpu_idle_pct",
                                      "busy_processes", "app_idle_minutes")):
            if app.get("quit") != "signal:TERM":
                raise ConfigError("only signal:TERM polite close is supported")
            if not re.fullmatch(r"[A-Za-z0-9_.+-]{1,15}", app["processes"][0]):
                raise ConfigError("first process must be an exact Linux comm name for close")
            exe = app.get("exe")
            if (not isinstance(exe, str) or not exe.startswith("/") or "\x00" in exe
                    or any(c in exe for c in "*?[]")):
                raise ConfigError("polite close requires an absolute exe path")
            timeout = app.get("close_timeout_s", 90)
            cpu = app.get("cpu_idle_pct", 3)
            idle_minutes = app.get("app_idle_minutes", 10)
            busy = app.get("busy_processes", [])
            if type(timeout) is not int or not 1 <= timeout <= 300:
                raise ConfigError("close_timeout_s must be between 1 and 300")
            if type(cpu) not in {int, float} or not 0 <= cpu <= 100:
                raise ConfigError("cpu_idle_pct must be between 0 and 100")
            if type(idle_minutes) not in {int, float} or not 1 <= idle_minutes <= 60:
                raise ConfigError("app_idle_minutes must be between 1 and 60")
            if not isinstance(busy, list) or any(not isinstance(p, str) or not p
                                                  or "\x00" in p for p in busy):
                raise ConfigError("busy_processes must be process-name fragments")
            checked_apps[name].update(quit="signal:TERM", exe=os.path.realpath(exe),
                                      close_timeout_s=timeout,
                                      cpu_idle_pct=cpu, app_idle_minutes=idle_minutes,
                                      busy_processes=busy)
    rafts = raw.get("rafts")
    if not isinstance(rafts, list) or not rafts:
        raise ConfigError("at least one raft must be configured")
    checked_rafts, seen = [], set()
    for raft in rafts:
        if not isinstance(raft, dict) or not _name(raft.get("label")) or raft["label"] in seen:
            raise ConfigError("raft labels must be unique simple names")
        seen.add(raft["label"])
        if raft.get("kind") != "sqlite":
            raise ConfigError("v0.1 accepts SQLite rafts only")
        if raft.get("app") not in checked_apps:
            raise ConfigError("every raft must name a configured app")
        checked_rafts.append({"label": raft["label"], "kind": "sqlite",
                              "path": _path(raft.get("path")), "app": raft["app"]})
    idle_time = raw.get("idle_time", "02:30")
    if not isinstance(idle_time, str) or not re.fullmatch(r"(?:[01][0-9]|2[0-3]):[0-5][0-9]", idle_time):
        raise ConfigError("idle_time must be HH:MM")
    minutes = raw.get("user_idle_minutes", 30)
    if type(minutes) is not int or not 1 <= minutes <= 1440:
        raise ConfigError("user_idle_minutes must be between 1 and 1440")
    stage_only = raw.get("stage_only", False)
    if type(stage_only) is not bool:
        raise ConfigError("stage_only must be true or false")
    keep_last_n = raw.get("keep_last_n", 5)
    if type(keep_last_n) is not int or not 1 <= keep_last_n <= 100:
        raise ConfigError("keep_last_n must be between 1 and 100")
    owner_exempt = raw.get("owner_exempt", list(DEFAULT_OWNER_EXEMPT))
    if (not isinstance(owner_exempt, list) or len(set(owner_exempt)) != len(owner_exempt)
            or any(kind not in OWNER_EXEMPT_KINDS for kind in owner_exempt)):
        raise ConfigError("owner_exempt accepts only: " + ", ".join(OWNER_EXEMPT_KINDS))
    return {"machine_label": label, "peer_label": peer,
            "transport": transport, "apps": checked_apps,
            "rafts": checked_rafts, "idle_time": idle_time,
            "user_idle_minutes": minutes, "stage_only": stage_only,
            "keep_last_n": keep_last_n, "owner_exempt": list(owner_exempt)}


def load(path=None):
    path = Path(path or default_path())
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
            raise ConfigError("config must be a private regular file (0600)")
        if info.st_size > 1024 * 1024:
            raise ConfigError("config too large")
        with path.open("rb") as stream:
            raw = tomllib.load(stream)
    except FileNotFoundError:
        raise ConfigError("config missing; run move init") from None
    except (OSError, ValueError, UnicodeError):
        raise ConfigError("config unreadable or invalid TOML") from None
    return validate(raw)


TEMPLATE = '''# Edit on each machine; keep this file mode 0600.
machine_label = "CHANGE-ME"
peer_label = "OTHER-MACHINE"
idle_time = "02:30"
user_idle_minutes = 30
stage_only = false
keep_last_n = 5
# Cursor's background agent worker does not hold app rafts by itself; it is
# still checked for open raft files. Use [] to treat it as an owner.
owner_exempt = ["cursor-agent-worker"]
transport = { kind = "rclone", remote = "raftcrypt:rafts" }

[apps.chat]
processes = ["CHANGE-ME-app", "CHANGE-ME-worker"]

[[rafts]]
label = "chat-state"
kind = "sqlite"
path = "~/CHANGE-ME/state.sqlite"
app = "chat"
'''
