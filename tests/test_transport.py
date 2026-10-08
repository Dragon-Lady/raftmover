"""Rclone packet completion and cleanup without a real cloud account."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

import pytest

import raftmover.transport as transport


def test_rclone_never_publishes_manifest_after_bad_remote_copy(tmp_path, monkeypatch):
    packet = tmp_path / "packet"
    packet.mkdir()
    (packet / "snapshot.sqlite").write_bytes(b"checked snapshot")
    (packet / "manifest.json").write_bytes(b"signed manifest")
    remote, commands = {}, []

    def command(argv, timeout=300):
        commands.append(argv)
        if argv[1:3] == ["config", "dump"]:
            return b'{"crypt":{"type":"crypt","remote":":local:/tmp"}}'
        if argv[1:3] == ["config", "providers"]:
            return b'[{"Prefix":"crypt","Overview":{"Virtual":true}}]'
        if argv[1] == "lsjson":
            return b"[]"
        if argv[1] == "purge":
            prefix = argv[-1] + "/"
            for key in list(remote):
                if key.startswith(prefix):
                    del remote[key]
            return b""
        if argv[1] == "lsf":
            prefix = argv[-1] + "/"
            return "\n".join(key[len(prefix):] for key in remote if key.startswith(prefix)).encode()
        assert argv[1] == "copyto"
        src, dst = argv[-2:]
        data = remote[src] if src.startswith("crypt:") else Path(src).read_bytes()
        if src.endswith("/incoming/" + "a" * 32 + "/snapshot.sqlite"):
            data = b"changed after upload"
        if dst.startswith("crypt:"):
            remote[dst] = data
        else:
            Path(dst).write_bytes(data)
        return b""

    monkeypatch.setattr(transport, "_command", command)
    with pytest.raises(transport.TransferError, match="transfer-hash-mismatch"):
        transport.Rclone("crypt:rafts").send(packet, "a" * 32)
    assert not any(path.endswith("manifest.json") for path in remote)
    assert not any("/.partial-" in path for path in remote)
    assert any(argv[1] == "purge" for argv in commands)


def test_rclone_sweeps_only_old_named_partial_directories(monkeypatch):
    old = (datetime.now(timezone.utc) - timedelta(days=9)).isoformat()
    new = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    entries = [
        {"Name": ".partial-" + "a" * 32, "IsDir": True, "ModTime": old},
        {"Name": ".partial-" + "b" * 32, "IsDir": True, "ModTime": new},
        {"Name": "c" * 32, "IsDir": True, "ModTime": old},
        {"Name": ".partial-" + "d" * 32, "IsDir": True,
         "ModTime": "2000-01-01T00:00:00Z"},
    ]
    purged = []

    def command(argv, timeout=300):
        if argv[1] == "lsjson":
            return json.dumps(entries).encode()
        purged.append(argv[-1])
        return b""

    monkeypatch.setattr(transport, "_command", command)
    transport.Rclone("crypt:rafts")._sweep_partials()
    assert purged == ["crypt:rafts/incoming/.partial-" + "a" * 32]
