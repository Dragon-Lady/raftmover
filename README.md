# Raft Mover

Raft Mover is a planned Linux-first handoff tool for closed SQLite chat data.
It will install Raft Ward as a required dependency and require explicit passes
before sending or adopting a frozen copy. This checkout is a supervised v0.1
prototype under development; installing it does not install or enable a timer.
Use manual moves while its interruption and desktop behavior are being reviewed.

Each pair of machines needs distinct labels, reciprocal `peer_label` entries,
and the same private `pair.key` on both sides. `move pair create` makes it on
the first machine; `move pair import FILE` installs a securely transferred
private copy on the second. Packet manifests are signed with HMAC-SHA256 and
authenticated before use. Never place the key in the packet transport.

New to rclone or cross-machine setup? Start with the
[beginner transport guide](https://github.com/Dragon-Lady/raftmover/blob/main/docs/transport-setup.md). It covers encrypted
cloud storage through rclone, SSH through rclone SFTP, and a private shared folder, plus the first
supervised round trip.

`move` receives waiting packets and then sends eligible rafts. `move pickup`
receives only; `move pickup --stage-only` checks packets without adopting.
Set `stage_only = true` in the private config to make that behavior the default.
`move --status` and `move report --format json` inspect local state without
moving data. `move restore RAFT-LABEL` uses the recorded pre-adopt backup only
after that backup passes its hash and Raft Ward checks. Review both histories
before restoring or using `move adopt RAFT-LABEL --keep-both`, which overrides
the first-pair and divergence refusal.

Each app's `processes` entries are matched against every same-user process's
name, executable path, and full command line. Any match holds that app's rafts
with `owning-app-running`, including a shell, script, or wrapper whose command
line merely mentions the app (for example `bash -c "... codex ..."`). Run Mover
from a plain shell and pick process names that only the app itself uses.

Cursor's background agent worker (`cursor-agent ... worker start`) does not
hold rafts by itself. `owner_exempt = ["cursor-agent-worker"]`, the default,
passes Raft Ward 0.1.5's fixed exemption for that worker only. The editor and
every other `cursor-agent` command still count as owners, and the worker still
blocks a move if it has the database or a sidecar open or looks like a
transfer. Set `owner_exempt = []` to treat the worker as an owner again; no
other values are accepted.

Bare `move` never closes an app. An experimental opt-in `quit = "signal:TERM"` app setting
allows `move --close` or a timer's `--auto` run to politely close an idle app.
Set `exe` to the main process's absolute executable path. The first configured
process name must be its exact Linux `comm` name. Mover requires one verified
root process. It checks a quiet CPU and database window, refuses listed busy
workers, signals only that root through a pidfd, and waits for Raft Ward to
confirm closure. It never
sends SIGKILL. If the idle hint or process identity is uncertain, that app's
rafts wait while independent rafts can continue. See the transport guide for
the config and current backend limits. The timer relies on logind's idle hint;
on desktops that do not publish it, including current COSMIC setups, `--auto`
prints `idle-unknown`, exits `4`, and does nothing. A process tree with an
Electron crashpad helper may make `--close` refuse. AppImage and snap executable
paths can also prevent an exact executable match. Manual moves remain available.

Exit codes: `0` completed, `1` integrity or transport failure, `2` usage or
configuration error, `3` held for review, `4` check inconclusive, `130` Ctrl-C,
and `143` SIGTERM. A held or inconclusive result never approves a move.

Mover keeps pre-adopt backups in its private state directory under `backups/`.
`move --status` and `move report` show each raft's backup count and total bytes.
Do not delete backups while a packet is pending or while reviewing a divergence.
For manual cleanup after both histories are settled, delete only backup files
that are not named by any lineage `backup` or `diverged_backup` field and are
not named by any pending receipt's `backup` field. Keep a separate verified
archive first if you may need an older copy.
`keep_last_n = 5` retains the newest acknowledged packets per raft. A receiver
signs an applied-packet acknowledgment only after applying it; a reviewed
decline has its own signed acknowledgment. Unacknowledged packets and older
receipts without a generation number are never pruned. Local
backups are not pruned by this setting.
If status says `pending-swap-ambiguous` or `pending-backup-missing`, keep the
current database, staged packet, and backups for supervised recovery.
After reviewing the current database and staged history, `move recover
RAFT-LABEL --accept-current` verifies and backs up the current database, marks
the packet declined with a signed acknowledgment, and breaks automatic lineage.
After the acknowledgment is confirmed, the declined staged copy is removed.
If acknowledgment is unavailable, the copy remains staged until a later retry
or a newer packet is adopted. The current database is never replaced by this
command.
