"""Raft Ward 0.1.5 owner exemption: Cursor's background agent worker."""
import os
import secrets
import sqlite3
import subprocess
import sys
import time

import pytest
from raftward.api import Result

from raftmover.config import ConfigError, TEMPLATE, tomllib, validate
from raftmover.engine import Engine


def raw_config(tmp_path, **extra):
    raw = {"machine_label": "A", "peer_label": "B",
           "transport": {"kind": "folder", "path": str(tmp_path / "shared")},
           "apps": {"chat": {"processes": ["unlikely-test-owner"]}},
           "rafts": [{"label": "chat-state", "kind": "sqlite",
                      "path": str(tmp_path / "a.sqlite"), "app": "chat"}]}
    raw.update(extra)
    return raw


def test_owner_exempt_defaults_to_cursor_agent_worker(tmp_path):
    assert validate(raw_config(tmp_path))["owner_exempt"] == ["cursor-agent-worker"]


def test_owner_exempt_can_be_turned_off(tmp_path):
    assert validate(raw_config(tmp_path, owner_exempt=[]))["owner_exempt"] == []


@pytest.mark.parametrize("value", ["cursor-agent-worker", ["cursor"], ["*"],
                                   ["cursor-agent-worker", "cursor-agent-worker"],
                                   [None], [["cursor-agent-worker"]],
                                   {"cursor-agent-worker": True}])
def test_owner_exempt_rejects_anything_but_known_kinds(tmp_path, value):
    with pytest.raises(ConfigError, match="owner_exempt accepts only"):
        validate(raw_config(tmp_path, owner_exempt=value))


def test_starter_template_states_the_default():
    assert tomllib.loads(TEMPLATE)["owner_exempt"] == ["cursor-agent-worker"]


def gate_engine(tmp_path, **extra):
    (tmp_path / "shared").mkdir(mode=0o700, exist_ok=True)
    key = tmp_path / "pair.key"
    key.write_bytes(os.urandom(32))
    key.chmod(0o600)
    return Engine(validate(raw_config(tmp_path, **extra)), tmp_path / "state", key_path=key)


@pytest.mark.parametrize("extra,expected", [({}, ["cursor-agent-worker"]),
                                            ({"owner_exempt": []}, [])])
def test_gate_receives_configured_owner_exempt(tmp_path, extra, expected):
    engine = gate_engine(tmp_path, **extra)
    calls = []

    def gate(path, owners, **kwargs):
        calls.append(kwargs)
        return Result("pass", "ok")

    engine.gate = gate
    engine._check_gate(engine.cfg["rafts"][0])
    assert calls[0]["owner_exempt"] == expected
    assert calls[0]["transfer_dirs"][0] == str(tmp_path / "a.sqlite")


def test_unvalidated_config_dict_keeps_the_default(tmp_path):
    engine = gate_engine(tmp_path)
    del engine.cfg["owner_exempt"]
    seen = []
    engine.gate = lambda *a, **k: seen.append(k["owner_exempt"]) or Result("pass", "ok")
    engine._check_gate(engine.cfg["rafts"][0])
    assert seen == [["cursor-agent-worker"]]


# Real /proc checks through the installed Raft Ward. The fake process runs a
# script named "cursor-agent-rmtest-<random>" so Raft Ward's structural worker
# check sees a cursor-agent program, and the owner pattern stays unique to this
# run. An optional file to hold open comes through the environment, not argv.
def start(tmp_path, marker, *args, hold=None, ready):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    script = bin_dir / marker
    script.write_text("import os, time\n"
                      "held = open(os.environ['RMTEST_HOLD'], 'rb') "
                      "if os.environ.get('RMTEST_HOLD') else None\n"
                      "time.sleep(30)\n")
    env = dict(os.environ)
    env.pop("RMTEST_HOLD", None)
    if hold is not None:
        env["RMTEST_HOLD"] = str(hold)
    process = subprocess.Popen([sys.executable, str(script), *args], env=env,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(500):
        if ready(process.pid):
            return process
        if process.poll() is not None:
            break
        time.sleep(0.01)
    process.terminate()
    process.wait(timeout=5)
    raise AssertionError("test process did not start")


def has_cmdline(marker):
    def ready(pid):
        try:
            return marker.encode() in open(f"/proc/{pid}/cmdline", "rb").read(4096)
        except FileNotFoundError:
            return False
    return ready


def has_open(path):
    def ready(pid):
        try:
            return any(os.readlink(f"/proc/{pid}/fd/{fd}") == str(path)
                       for fd in os.listdir(f"/proc/{pid}/fd"))
        except (FileNotFoundError, PermissionError):
            return False
    return ready


def real_engine(tmp_path, marker, **extra):
    (tmp_path / "shared").mkdir(mode=0o700, exist_ok=True)
    key = tmp_path / "pair.key"
    key.write_bytes(os.urandom(32))
    key.chmod(0o600)
    db = tmp_path / "a.sqlite"
    with sqlite3.connect(db) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS t(x)")
    raw = raw_config(tmp_path, **extra)
    raw["apps"]["chat"]["processes"] = [marker]
    return Engine(validate(raw), tmp_path / "state", key_path=key), db


def dry_check(engine):
    try:
        engine._check_gate(engine.cfg["rafts"][0])
        return "pass"
    except Exception as exc:
        return str(exc)


@pytest.mark.skipif(sys.platform != "linux", reason="Raft Ward process gating is Linux-only")
def test_real_proc_cursor_agent_worker(tmp_path):
    marker = "cursor-agent-rmtest-" + secrets.token_hex(4)
    worker = start(tmp_path, marker, "worker", "start", ready=has_cmdline(marker))
    try:
        engine, _ = real_engine(tmp_path, marker)
        assert dry_check(engine) == "pass"
        engine, _ = real_engine(tmp_path, marker, owner_exempt=[])
        assert dry_check(engine) == "owning-app-running"
    finally:
        worker.terminate()
        worker.wait(timeout=5)


@pytest.mark.skipif(sys.platform != "linux", reason="Raft Ward process gating is Linux-only")
def test_real_proc_other_cursor_agent_commands_still_own(tmp_path):
    marker = "cursor-agent-rmtest-" + secrets.token_hex(4)
    other = start(tmp_path, marker, "chat", ready=has_cmdline(marker))
    try:
        engine, _ = real_engine(tmp_path, marker)
        assert dry_check(engine) == "owning-app-running"
    finally:
        other.terminate()
        other.wait(timeout=5)


@pytest.mark.skipif(sys.platform != "linux", reason="Raft Ward process gating is Linux-only")
def test_real_proc_exempt_worker_holding_the_raft_still_blocks(tmp_path):
    marker = "cursor-agent-rmtest-" + secrets.token_hex(4)
    db = tmp_path / "a.sqlite"
    with sqlite3.connect(db) as conn:
        conn.execute("CREATE TABLE t(x)")
    worker = start(tmp_path, marker, "worker", "start", hold=db, ready=has_open(db))
    try:
        engine, _ = real_engine(tmp_path, marker)
        assert dry_check(engine) == "target-handle-open"
    finally:
        worker.terminate()
        worker.wait(timeout=5)
