"""Run the supplied crash matrix only against isolated scratch databases."""
import json
import subprocess
import sys
from pathlib import Path

import pytest


SCRIPT = Path(__file__).with_name("r5_crash_matrix.py")
STAGES = (
    "after-backup", "after-temp", "after-pending", "after-rename",
    "after-lineage", "after-applied", "after-stage-removed", "after-ack-flag",
)


@pytest.mark.parametrize("stage", STAGES)
@pytest.mark.parametrize("receiver_edit", [False, True])
def test_recovery_preserves_receiver_and_cleans_temp(tmp_path, stage, receiver_edit):
    setup = subprocess.run([sys.executable, str(SCRIPT), "setup", str(tmp_path)],
                           capture_output=True, text=True, check=False, timeout=30)
    assert setup.returncode == 0, setup.stderr
    crash = subprocess.run([sys.executable, str(SCRIPT), "crash", str(tmp_path), stage],
                           capture_output=True, text=True, check=False, timeout=30)
    assert crash.returncode == -9, (stage, crash.returncode, crash.stderr)
    mode = "recover-edit" if receiver_edit else "recover"
    recovery = subprocess.run([sys.executable, str(SCRIPT), mode, str(tmp_path)],
                              capture_output=True, text=True, check=False, timeout=30)
    assert recovery.returncode == 0, recovery.stderr
    result = json.loads(recovery.stdout.splitlines()[-1])
    assert result["temps_final"] == 0
    if receiver_edit:
        assert "receiver-edit-after-crash" in result["rows_final"]
    else:
        assert "sender-new" in result["rows_final"]
