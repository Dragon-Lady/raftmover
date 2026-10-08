"""Conservative Linux user-idle hint. Unknown always means not idle."""
import os
import subprocess
import time


def user_idle_state(minutes):
    # A systemd --user timer has no XDG_SESSION_ID, so prefer the aggregate
    # user hint. If unavailable, inspect the invoking graphical session.
    probes = [["loginctl", "show-user", str(os.getuid()), "-p", "IdleHint",
               "-p", "IdleSinceHintMonotonic"]]
    session = os.environ.get("XDG_SESSION_ID", "")
    if session.isalnum():
        probes.append(["loginctl", "show-session", session, "-p", "IdleHint",
                       "-p", "IdleSinceHintMonotonic"])
    for argv in probes:
        try:
            proc = subprocess.run(argv, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, timeout=3,
                                  check=False, text=True)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if proc.returncode:
            continue
        fields = dict(line.split("=", 1) for line in proc.stdout.splitlines() if "=" in line)
        if "IdleHint" not in fields or "IdleSinceHintMonotonic" not in fields:
            continue
        if fields.get("IdleHint") != "yes":
            return "active" if fields.get("IdleHint") == "no" else "unknown"
        try:
            since = int(fields["IdleSinceHintMonotonic"])
            if since <= 0:
                return "unknown"
            elapsed = (time.monotonic_ns() // 1000 - since) / 60_000_000
        except (ValueError, KeyError):
            return "unknown"
        return "idle" if elapsed >= minutes else "active"
    return "unknown"


def user_idle(minutes):
    return user_idle_state(minutes) == "idle"
