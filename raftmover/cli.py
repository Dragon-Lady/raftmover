"""Minimal, content-free operator interface."""
import argparse
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import sys

from . import __version__
from .app_close import CloseError, close_if_idle
from .config import ConfigError, TEMPLATE, default_path, load
from .engine import Engine, MoveError
from .idle import user_idle, user_idle_state
from .safety import SafetyError, new_private_file, private_dir
from .transport import TransferError


class Terminated(BaseException):
    pass


def _term(_signal, _frame):
    raise Terminated


def _args(argv):
    parser = argparse.ArgumentParser(
        prog=Path(sys.argv[0]).name,
        description="Checked SQLite handoff; bare move receives, then sends",
        epilog="Exit codes: 0 completed, 1 integrity/transport failure, 2 usage/config, "
               "3 held for review, 4 check inconclusive, 130 Ctrl-C, 143 SIGTERM.")
    parser.add_argument("--version", action="version", version=f"raftmover {__version__}")
    parser.add_argument("--config", type=Path, default=None, help="private config file")
    parser.add_argument("--status", action="store_true", help="show local raft state")
    parser.add_argument("--dry-run", action="store_true", help="check owners without moving data")
    parser.add_argument("--auto", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--close", action="store_true", help="politely close configured idle apps before moving")
    sub = parser.add_subparsers(dest="command")
    pickup = sub.add_parser("pickup", help="receive and check waiting packets")
    pickup.add_argument("--stage-only", action="store_true", help="check and stage without adoption")
    adopt = sub.add_parser("adopt", help="manually adopt one staged raft")
    adopt.add_argument("raft", help="raft label from config")
    adopt.add_argument("--keep-both", action="store_true",
                       help="override divergence or first-pair refusal after manual review; back up receiver first")
    adopt.add_argument("--packet", metavar="ID",
                       help="choose an exact staged packet ID after reviewing multiple candidates")
    restore = sub.add_parser("restore", help="restore the last pre-adopt backup")
    restore.add_argument("raft", help="raft label from config")
    recover = sub.add_parser("recover", help="keep a reviewed receiver after an ambiguous move")
    recover.add_argument("raft", help="raft label from config")
    recover.add_argument("--accept-current", action="store_true", required=True,
                         help="keep current database, back it up, and break automatic lineage")
    sub.add_parser("init", help="write a private starter config")
    pair = sub.add_parser("pair", help="create or import the private pair key")
    pair_actions = pair.add_subparsers(dest="pair_action", required=True)
    pair_actions.add_parser("create", help="make a new key on the first machine")
    pair_import = pair_actions.add_parser("import", help="copy the same key from a private file")
    pair_import.add_argument("file", type=Path, help="private 0600 key file")
    sub.add_parser("print-timer", help="print a timer template; does not install it")
    report = sub.add_parser("report", help="show local status in a chosen format")
    report.add_argument("--format", choices=("text", "json", "md", "html"),
                        default="text", help="report output format")
    args = parser.parse_args(argv)
    if ((args.status and (args.dry_run or args.command is not None or args.close))
            or (args.dry_run and (args.command is not None or args.close))
            or (args.auto and (args.status or args.dry_run or args.command is not None or args.close))
            or (args.close and args.command is not None)):
        parser.error("choose one action: --status, --dry-run, --auto, --close, or a command")
    return args


def _print_rows(rows, fmt="text"):
    if fmt == "json":
        print(json.dumps(rows, sort_keys=True))
    elif fmt == "md":
        print("| Raft | Status | Reason | Backups | Backup bytes |\n|---|---|---|---:|---:|")
        for row in rows:
            print(f'| {row["raft"]} | {row["status"]} | {row.get("reason", "")} | '
                  f'{row.get("backup_count", "")} | {row.get("backup_bytes", "")} |')
    elif fmt == "html":
        from html import escape
        print("<table><tr><th>Raft</th><th>Status</th><th>Reason</th>"
              "<th>Backups</th><th>Backup bytes</th></tr>")
        for row in rows:
            print("<tr>" + "".join("<td>" + escape(str(row.get(k, ""))) + "</td>"
                                       for k in ("raft", "status", "reason", "backup_count",
                                                 "backup_bytes")) + "</tr>")
        print("</table>")
    else:
        for row in rows:
            print(f'{row["raft"]}: {row["status"]}' +
                  (f' ({row["reason"]})' if row.get("reason") else "") +
                  (f' [backups: {row["backup_count"]}, {row["backup_bytes"]} bytes]'
                   if "backup_count" in row else ""))


def _exit_code(rows):
    if all(r["status"] in {"sent", "adopted", "restored", "unchanged",
                             "recovered", "eligible"} for r in rows):
        return 0
    if any(r["reason"].startswith(("ward-verify-failed", "transport-failed",
                                  "transport-unavailable", "transfer-hash-mismatch",
                                  "sqlite-")) for r in rows if "reason" in r):
        return 1
    if any(r.get("reason", "").startswith(("ward-gate-inconclusive",
                                           "ward-verify-inconclusive", "runtime-error",
                                           "app-process-state-unknown", "app-database-state-unknown",
                                           "transport-config-unverifiable", "app-gate-inconclusive",
                                           "app-close-gate-inconclusive", "ack-state-unverifiable",
                                           "receipt-state-unverifiable"))
           for r in rows):
        return 4
    return 3


def _single_row(label, action):
    try:
        return action()
    except MoveError as exc:
        if str(exc) == "unknown-raft":
            raise
        return {"raft": label, "status": "held", "reason": str(exc)}
    except (SafetyError, TransferError) as exc:
        return {"raft": label, "status": "held", "reason": str(exc)}
    except Exception:
        return {"raft": label, "status": "held", "reason": "runtime-error"}


def _init(path):
    private_dir(path.parent)
    fd = new_private_file(path)
    try:
        os.write(fd, TEMPLATE.encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    print("Created private config. Edit its explicit app and raft entries before moving data.")


def _pair(args, config_path):
    destination = config_path.parent / "pair.key"
    private_dir(destination.parent)
    key = secrets.token_bytes(32) if args.pair_action == "create" else Engine._load_key(args.file)
    fd = new_private_file(destination)
    try:
        view = memoryview(key)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)
    print("Pair key stored privately. Place the same key on the other machine through a trusted channel; never use the packet folder.")


def _timer(cfg, config_path):
    command = shutil.which("move") or shutil.which("raftmove")
    if not command:
        raise MoveError("move-command-not-found")
    command = str(Path(command).resolve())
    if any(c.isspace() for c in command):
        raise MoveError("timer-command-path-has-spaces")
    explicit = Path(config_path).resolve() != default_path().resolve()
    config_arg = ""
    if explicit:
        config_path = str(Path(config_path).resolve())
        if any(c.isspace() for c in config_path):
            raise MoveError("timer-config-path-has-spaces")
        config_arg = " --config " + config_path
    print("# Save as ~/.config/systemd/user/raftmover.service")
    print("[Unit]\nDescription=Raft Mover checked handoff\n[Service]\nType=oneshot")
    print(f"ExecStart={command}{config_arg} --auto")
    print("# Save as ~/.config/systemd/user/raftmover.timer")
    print("[Unit]\nDescription=Raft Mover daily idle attempt\n[Timer]")
    hour, minute = cfg["idle_time"].split(":")
    print(f"OnCalendar=*-*-* {hour}:{minute}:00\nPersistent=false\nUnit=raftmover.service")
    print("[Install]\nWantedBy=timers.target")
    print(f"# cron alternative: {int(minute)} {int(hour)} * * * {command}{config_arg} --auto")


def main(argv=None):
    previous_term = signal.getsignal(signal.SIGTERM)
    signal.signal(signal.SIGTERM, _term)
    try:
        return _main(argv)
    except Terminated:
        print("cancelled", file=sys.stderr)
        return 143
    finally:
        signal.signal(signal.SIGTERM, previous_term)


def _main(argv=None):
    args = _args(argv)
    path = args.config or default_path()
    if args.command == "init":
        try:
            _init(path)
            return 0
        except FileExistsError:
            print("Config already exists; left untouched.", file=sys.stderr)
            return 2
        except (SafetyError, OSError):
            print("Could not create a private config.", file=sys.stderr)
            return 2
    if args.command == "pair":
        try:
            _pair(args, path)
            return 0
        except FileExistsError:
            print("Pair key already exists; left untouched.", file=sys.stderr)
            return 2
        except (MoveError, SafetyError, OSError) as exc:
            print(str(exc) if isinstance(exc, (MoveError, SafetyError)) else "pair-key-error",
                  file=sys.stderr)
            return 2
    if args.command == "print-timer":
        try:
            _timer(load(path), path)
            return 0
        except (MoveError, ConfigError) as exc:
            print(str(exc), file=sys.stderr)
            return 2
    try:
        cfg = load(path)
        engine = Engine(cfg, key_path=path.parent / "pair.key")
        if args.auto:
            state = user_idle_state(cfg["user_idle_minutes"])
            if state != "idle":
                print(("idle-unknown" if state == "unknown" else "not-idle")
                      + ": no raft or app touched")
                return 4 if state == "unknown" else 3
        if args.status or args.command == "report":
            rows = engine.status()
            _print_rows(rows, args.format if args.command == "report" else "text")
            return 0
        if args.dry_run:
            rows = []
            for raft in cfg["rafts"]:
                try:
                    engine._check_gate(raft)
                    rows.append({"raft": raft["label"], "status": "eligible", "reason": "owner-closed"})
                except Exception as exc:
                    reason = str(exc) if isinstance(exc, (MoveError, SafetyError)) else "runtime-error"
                    rows.append({"raft": raft["label"], "status": "held", "reason": reason})
            _print_rows(rows)
            return _exit_code(rows)
        with engine.locked():
            hold_labels = {}
            if args.auto or args.close:
                for name, app in cfg["apps"].items():
                    rafts = [r for r in cfg["rafts"] if r["app"] == name]
                    try:
                        close_if_idle(engine, name, rafts, auto=args.auto,
                                      user_idle=lambda: user_idle(cfg["user_idle_minutes"]))
                    except CloseError as exc:
                        hold_labels.update({r["label"]: str(exc) for r in rafts})
                if args.auto:
                    state = user_idle_state(cfg["user_idle_minutes"])
                    if state != "idle":
                        print(("idle-unknown" if state == "unknown" else "not-idle")
                              + ": no raft moved")
                        return 4 if state == "unknown" else 3
            if args.command == "adopt":
                rows = list(engine.recovery_rows) + [
                    _single_row(args.raft, lambda: engine.adopt(
                        args.raft, args.packet, keep_both=args.keep_both))]
            elif args.command == "restore":
                rows = list(engine.recovery_rows) + [
                    _single_row(args.raft, lambda: engine.restore(args.raft))]
            elif args.command == "recover":
                rows = [row for row in engine.recovery_rows if row["raft"] != args.raft] + [
                    _single_row(args.raft, lambda: engine.recover_accept_current(args.raft))]
            elif args.command == "pickup":
                rows = engine.pickup(stage_only=args.stage_only)
            else:
                rows = engine.pickup(hold_labels=hold_labels) + engine.send(hold_labels=hold_labels)
        _print_rows(rows)
        return _exit_code(rows)
    except KeyboardInterrupt:
        print("cancelled", file=sys.stderr)
        return 130
    except TransferError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except (ConfigError, MoveError, SafetyError) as exc:
        print(str(exc), file=sys.stderr)
        return 3 if str(exc) == "another-run-active" else 2
    except (OSError, ValueError, TypeError):
        print("runtime-error", file=sys.stderr)
        return 4
    except Exception:
        print("runtime-error", file=sys.stderr)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
