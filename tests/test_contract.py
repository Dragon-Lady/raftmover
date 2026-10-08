import os
from pathlib import Path
import signal
import stat
import time

import pytest

from raftmover import cli, idle
import raftmover.engine as engine_module
from raftmover.config import ConfigError, validate
from raftmover.engine import Engine, MoveError
import raftmover.transport as transport_module
from raftward.api import Result
from test_security import add, initial_handoff, pair, rows


def test_pair_key_cli_creates_private_file_and_imports_without_printing_it(tmp_path, capsys):
    first = tmp_path / "one" / "config.toml"
    second = tmp_path / "two" / "config.toml"
    assert cli.main(["--config", str(first), "init"]) == 0
    assert cli.main(["--config", str(second), "init"]) == 0
    assert cli.main(["--config", str(first), "pair", "create"]) == 0
    original = first.parent / "pair.key"
    assert len(original.read_bytes()) == 32
    assert stat.S_IMODE(original.stat().st_mode) == 0o600
    assert cli.main(["--config", str(second), "pair", "import", str(original)]) == 0
    assert (second.parent / "pair.key").read_bytes() == original.read_bytes()
    output = capsys.readouterr()
    assert original.read_bytes().hex() not in output.out + output.err
    assert cli.main(["--config", str(first), "pair", "create"]) == 2
    assert original.read_bytes() == (second.parent / "pair.key").read_bytes()


def test_restore_verifies_backup_and_breaks_auto_lineage(tmp_path):
    a, b, paths, shared = pair(tmp_path)
    add(paths[0], "from A")
    initial_handoff(a, b)
    assert rows(paths[1]) == ["base", "from A"]
    last = b._state("chat-state")["last_hash"]
    with b.locked():
        assert b.restore("chat-state")["status"] == "restored"
    assert rows(paths[1]) == ["base"]
    state = b._state("chat-state")
    assert state["last_hash"] == last
    assert state["lineage_broken"] is True
    backup = b.root / "backups" / state["backup"]
    backup.write_bytes(b"tampered")
    with b.locked():
        with pytest.raises(Exception, match="backup-hash-mismatch"):
            b.restore("chat-state")


def test_restore_keeps_receiver_file_mode(tmp_path):
    a, b, paths, _ = pair(tmp_path)
    paths[1].chmod(0o644)
    add(paths[0], "from sender")
    initial_handoff(a, b)
    with b.locked():
        b.restore("chat-state")
    assert stat.S_IMODE(paths[1].stat().st_mode) == 0o644


def test_manual_recover_requires_explicit_current_choice():
    with pytest.raises(SystemExit) as exc:
        cli._args(["recover", "chat-state"])
    assert exc.value.code == 2
    assert cli._args(["recover", "chat-state", "--accept-current"]).accept_current


def test_second_run_cannot_take_active_lock(tmp_path):
    sender, _, _, _ = pair(tmp_path)
    second = Engine(sender.cfg, sender.root, key_path=tmp_path / "pair.key")
    with sender.locked():
        with pytest.raises(MoveError, match="another-run-active"):
            with second.locked():
                pass


@pytest.mark.parametrize("interruption,code", [("keyboard", 130), ("term", 143)])
def test_interrupted_folder_send_cleans_private_copies(tmp_path, monkeypatch,
                                                       interruption, code):
    sender, _, paths, shared = pair(tmp_path)
    before = paths[0].read_bytes()
    monkeypatch.setattr(cli, "load", lambda path: sender.cfg)
    monkeypatch.setattr(cli, "Engine", lambda cfg, key_path: sender)
    real_copy = transport_module.copy_private

    def interrupt_partial(source, destination):
        if destination.name == "snapshot.sqlite" and ".partial-" in str(destination):
            if interruption == "term":
                signal.raise_signal(signal.SIGTERM)
            raise KeyboardInterrupt
        return real_copy(source, destination)

    monkeypatch.setattr(transport_module, "copy_private", interrupt_partial)
    assert cli.main([]) == code
    assert paths[0].read_bytes() == before
    assert not list((sender.root / "runs").glob("run-*"))
    assert not list((shared / "incoming").glob(".partial-*"))


def test_sigint_during_frozen_check_reports_cancel_without_state(tmp_path, monkeypatch):
    sender, _, paths, _ = pair(tmp_path)
    before = paths[0].read_bytes()
    monkeypatch.setattr(cli, "load", lambda path: sender.cfg)
    monkeypatch.setattr(cli, "Engine", lambda cfg, key_path: sender)
    sender.verify = lambda *args, **kwargs: (_ for _ in ()).throw(KeyboardInterrupt)
    assert cli.main([]) == 130
    assert paths[0].read_bytes() == before
    assert not list((sender.root / "runs").glob("run-*"))
    assert not list((sender.root / "receipts").glob("*.json"))


def test_sigterm_before_swap_keeps_discriminator_and_receiver_edit(tmp_path, monkeypatch):
    sender, receiver, paths, _ = pair(tmp_path)
    add(paths[0], "from sender")
    initial_handoff(sender, receiver)
    add(paths[0], "second")
    with sender.locked():
        assert sender.send()[0]["status"] == "sent"
        packet_id = sender._state("chat-state")["packet"]
    with receiver.locked():
        receiver.pickup(stage_only=True)
    before = paths[1].read_bytes()
    monkeypatch.setattr(cli, "load", lambda path: receiver.cfg)
    monkeypatch.setattr(cli, "Engine", lambda cfg, key_path: receiver)
    real_replace = engine_module.os.replace

    def interrupt_at_swap(src, dst, *args, **kwargs):
        if kwargs.get("dst_dir_fd") is not None and dst == paths[1].name:
            signal.raise_signal(signal.SIGTERM)
        return real_replace(src, dst, *args, **kwargs)

    monkeypatch.setattr(engine_module.os, "replace", interrupt_at_swap)
    assert cli.main(["adopt", "chat-state"]) == 143
    monkeypatch.setattr(engine_module.os, "replace", real_replace)
    assert paths[1].read_bytes() == before
    pending = receiver._receipt(packet_id)
    assert pending.exists()
    assert len(list(paths[1].parent.glob(".raftmover-*"))) == 1
    add(paths[1], "receiver edit after cancel")
    with receiver.locked():
        assert any(row["reason"] == "diverged-or-unpaired"
                   for row in receiver.recovery_rows)
    assert rows(paths[1])[-1] == "receiver edit after cancel"
    assert not list((receiver.root / "runs").glob("run-*"))


def test_restored_copy_cannot_auto_roll_back_peer(tmp_path):
    a, b, paths, shared = pair(tmp_path)
    add(paths[0], "from A")
    initial_handoff(a, b)
    with b.locked():
        b.restore("chat-state")
        assert b.send()[0]["status"] == "sent"
    before = paths[0].read_bytes()
    with a.locked():
        result = a.pickup()
    assert any(r["status"] == "staged" for r in result)
    assert paths[0].read_bytes() == before


def test_missing_pair_key_and_unexpected_verify_fail_closed(tmp_path):
    a, b, paths, shared = pair(tmp_path)
    with pytest.raises(MoveError, match="pair-key-missing"):
        Engine(a.cfg, tmp_path / "no-key-state", key_path=tmp_path / "missing")
    assert not (tmp_path / "no-key-state").exists()
    a.verify = lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("secret path"))
    with a.locked():
        result = a.send()
    assert result == [{"raft": "chat-state", "status": "held", "reason": "runtime-error"}]
    assert "secret path" not in repr(result)


def test_send_interrupt_cleans_private_run(tmp_path):
    a, b, paths, shared = pair(tmp_path)
    before = paths[0].read_bytes()

    class Interrupted:
        def send(self, packet, packet_id):
            raise KeyboardInterrupt

    a.transport = Interrupted()
    with pytest.raises(KeyboardInterrupt):
        with a.locked():
            a.send()
    assert list((a.root / "runs").glob("run-*")) == []
    assert paths[0].read_bytes() == before


def test_user_timer_uses_aggregate_logind_hint_without_session_id(monkeypatch):
    monkeypatch.delenv("XDG_SESSION_ID", raising=False)
    now = time.monotonic_ns() // 1000

    class Result:
        returncode = 0
        stdout = f"IdleHint=yes\nIdleSinceHintMonotonic={now - 31 * 60_000_000}\n"

    seen = []
    def run(argv, **kwargs):
        seen.append(argv)
        return Result()
    monkeypatch.setattr(idle.subprocess, "run", run)
    assert idle.user_idle(30) is True
    assert seen[0][:2] == ["loginctl", "show-user"]


def test_opt_in_close_config_and_unimplemented_rsync_are_explicit(tmp_path):
    raw = {"machine_label": "A", "peer_label": "B",
           "transport": {"kind": "folder", "path": str(tmp_path)},
           "apps": {"chat": {"processes": ["chat"], "quit": "signal:TERM",
                             "exe": "/usr/bin/chat"}},
           "rafts": [{"label": "chat", "kind": "sqlite", "path": str(tmp_path / "db"), "app": "chat"}]}
    assert validate(raw)["apps"]["chat"]["quit"] == "signal:TERM"
    raw["apps"]["chat"]["quit"] = "signal:KILL"
    with pytest.raises(ConfigError, match="only signal:TERM"):
        validate(raw)
    raw["apps"]["chat"].pop("quit")
    raw["transport"] = {"kind": "rsync", "dest": "host:~/rafts"}
    with pytest.raises(ConfigError, match="rsync is not implemented"):
        validate(raw)


def test_manual_adopt_exit_codes_match_dry_run(tmp_path, monkeypatch, capsys):
    a, b, paths, _ = pair(tmp_path)
    initial_handoff(a, b)
    add(paths[0], "next")
    with a.locked():
        a.send()
    with b.locked():
        b.pickup(stage_only=True)
    monkeypatch.setattr(cli, "load", lambda _: b.cfg)
    monkeypatch.setattr(cli, "Engine", lambda *args, **kwargs: b)
    b.gate = lambda *args, **kwargs: Result("fail", "owning-app-running")
    assert cli.main(["--dry-run"]) == 3
    assert cli.main(["adopt", "chat-state"]) == 3
    b.gate = lambda *args, **kwargs: Result("inconclusive", "process-state-unknown")
    assert cli.main(["--dry-run"]) == 4
    assert cli.main(["adopt", "chat-state"]) == 4
    output = capsys.readouterr()
    assert "owning-app-running" in output.out
    assert "ward-gate-inconclusive" in output.out


def test_conflicting_actions_are_usage_errors(capsys):
    for argv in (["--status", "pickup"], ["--dry-run", "adopt", "chat-state"],
                 ["--close", "pickup"], ["--close", "--status"]):
        with pytest.raises(SystemExit) as exc:
            cli._args(argv)
        assert exc.value.code == 2
    with pytest.raises(SystemExit) as exc:
        cli._args(["adopt", "--help"])
    assert exc.value.code == 0
    assert "override divergence or first-pair refusal" in capsys.readouterr().out
    assert cli._args(["--close"]).close


def test_print_timer_preserves_nondefault_config(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli.shutil, "which", lambda name: "/usr/bin/move" if name == "move" else None)
    config = tmp_path / "custom" / "config.toml"
    cli._timer({"idle_time": "04:05"}, config)
    output = capsys.readouterr().out
    assert f"ExecStart=/usr/bin/move --config {config} --auto" in output
    assert f"5 4 * * * /usr/bin/move --config {config} --auto" in output
