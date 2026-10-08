# Beginner guide: get rafts between two Linux computers

Raft Mover copies a **closed, checked snapshot**, not a live SQLite database.
It includes Raft Ward and runs its checks before sending and before adopting a
snapshot. This is a setup guide for the planned release; the local draft is
not cleared for unattended use. Once it is reviewed, start with a manual
`move --dry-run`; install a timer with `move print-timer` only after one
supervised move and a return move both work. If a check cannot establish a
pass, no database is sent or adopted.

You need Raft Mover on **both** computers, an explicit list of apps and database
paths for each one, and one transport below. The database paths can differ;
their raft labels must match. Keep the computers' clocks reasonably accurate.
Give each machine a different `machine_label` and set its `peer_label` to the
other machine's label. The sender cannot inspect the other machine through a
cloud or folder transport; the receiver re-checks **its own** owning app
before reading or replacing its database.
Never point a cloud sync tool directly at a live chat database or its `-wal`,
`-shm`, or `-journal` files. Do not run `rclone sync` on an app's data directory.
If a machine has a OneDrive sync mount, **do not point a raft or folder
transport at that mount**. It is not a safe live database location or the
authoritative cloud endpoint. For OneDrive packets, use the configured rclone
remote directly, through `raftcrypt:rafts` in the example below.

## Pair the two machines before moving data

Raft Mover requires the **same private 32-byte pair key on both machines**.
The key signs each packet manifest; a packet without a valid signature is
rejected even if its SQLite checks pass. It is separate from the rclone crypt
password and must never be stored in the shared packet folder, an ordinary
cloud remote, a chat message, or a repository.

1. Run `move init` on each machine and edit its private config. Use matching
   raft labels, distinct `machine_label` values, and reciprocal `peer_label`
   values.
2. On one machine only, run `move pair create`. It creates
   `pair.key` beside that machine's config as a private `0600` file (normally
   `~/.config/raftmover/pair.key`). Do **not** run
   `move pair create` independently on the second machine; two keys will not
   match.
3. Copy that exact file to the second machine through verified SSH or an
   encrypted removable drive. Keep the copy private and outside the Raft
   Mover packet transport. On the second machine, make a private `0600` local
   copy and run `move pair import /absolute/path/to/private-copy`.
4. Remove the temporary import copy after the command succeeds. Keep a secure
   backup of the pair key; if it is lost on either machine, pending packets
   cannot be authenticated until the same key is restored.

## Option A: encrypted cloud storage with rclone

These steps use OneDrive as an example. Rclone supports [other storage
providers](https://rclone.org/overview/) too. The names below are examples;
pick names you recognize and use the same encrypted folder on both computers.

1. Install rclone 1.75.1 or newer using your operating system's package manager
   or the [official installation guide](https://rclone.org/install/). Run
   `rclone version` to confirm it is available. Mover's safety preflight needs
   the backend details from `rclone config providers`; an older rclone without
   those details is refused.
2. On the first computer, run `rclone config`. Choose **New remote**, name it
   `raftcloud`, and choose **Microsoft OneDrive** (select by name because menu
   numbers can change). Follow the browser sign-in and drive selection prompts.
   Save the remote. Rclone's [OneDrive setup guide](https://rclone.org/onedrive/)
   describes the prompts. Do not paste OAuth tokens into Raft Mover's config.
3. Run `rclone lsf raftcloud:`. A successful command confirms rclone can list
   that cloud account. An empty list is fine if the drive is empty.
4. Run `rclone config` again. Make another **New remote** called `raftcrypt`;
   choose **Encrypt/Decrypt a remote** (`crypt`). For the remote to encrypt,
   enter `raftcloud:RaftMoverEncrypted`. Choose standard filename encryption
   and directory-name encryption. Choose a strong crypt password and a separate
   salt/password2 if prompted; rclone can generate them. Save **both** in your
   password manager. Confirm the configuration. See the official
   [crypt guide](https://rclone.org/crypt/).
   If you lose the crypt password and salt **and** every usable copy of the
   crypt configuration, the encrypted packets cannot be decrypted. Keep both
   secrets in a password manager and keep a separate, securely backed-up copy
   of the configuration. Retain local pre-adopt backups too.
5. Run `rclone lsf raftcrypt:`. This tests access through the encrypted layer.
   Use `raftcrypt:` for Raft Mover, never the underlying
   `raftcloud:RaftMoverEncrypted` path. Rclone's crypt layer encrypts locally
   before upload; bypassing it sends plaintext.
6. On the second computer, repeat the OneDrive remote setup for the **same
   account/drive**. Make its crypt remote point to the same dedicated folder
   and enter the **same crypt password and salt**. Run `rclone lsf raftcrypt:`
   there too. Remote names can differ, but each machine's Raft Mover config
   must name its own crypt remote.
7. In each machine's private Raft Mover config, select the encrypted remote:

   ```toml
   transport = { kind = "rclone", remote = "raftcrypt:rafts" }
   ```

Rclone's config contains cloud credentials and the crypt password in a lightly
obscured form. Keep it private (mode `0600` on Linux), back it up securely, and
never paste it into chat, logs, tickets, or a repository. Run
`rclone config file` to locate it. An encrypted rclone config is possible, but
its separate **config encryption password cannot be recovered** if lost.
Save that password in your password manager too. An unattended timer must have
a safe way to unlock the config; do not put the password in a command line,
unit file, environment variable containing the password, or Raft Mover's TOML.

For a Linux user timer, rclone supports `RCLONE_PASSWORD_COMMAND`: its value is
the **path to a helper**, not the password. One option is to store the config
password in an existing user password store such as `pass`, then have a private
helper call `pass show rclone/config`. Set `RCLONE_PASSWORD_COMMAND` in the
`[Service]` section of the printed user unit to the helper's absolute path:

```ini
Environment=RCLONE_PASSWORD_COMMAND=/path/to/helper
```

That line contains a command path, not the secret. Keep the helper executable only by
you (mode `0700`); rclone reads the password from the helper's standard output,
which should contain only that password and no other text. The helper must
write no log. Test a read-only `rclone lsf raftcrypt:` from the same user
service context before enabling the timer. If the password store needs an
interactive unlock or is unavailable, the scheduled move must fail closed;
use a supervised manual move instead. See rclone's
[configuration encryption and password-command guide](https://rclone.org/docs/#configuration-encryption).

## Option B: SSH between machines through rclone SFTP (no cloud account)

If both machines can reach one packet host, rclone's
[SFTP backend](https://rclone.org/sftp/) can use SSH for the checked packet
transport. Pick **one shared packet store** on one machine or a third host.
On the host, create a private `rafts/incoming` directory with `umask 077`;
the host's Mover can use:

```toml
transport = { kind = "rclone", remote = ":local:/absolute/path/to/rafts" }
```

On the peer,
configure one SFTP remote whose `raftssh:rafts` path resolves to that **same**
store. Do not point the two machines at each other's separate packet folders.
Use key or agent authentication. Configure `known_hosts_file` with a host key
verified through a trusted channel (or verified pinned `host_keys`). Mover
refuses an SFTP remote without this setting; rclone itself does not check host
keys by default. Verify `rclone lsf raftssh:rafts/incoming` before a first move.
Then select that remote on the peer:

```toml
transport = { kind = "rclone", remote = "raftssh:rafts" }
```

The server directory must be private to the receiving user. Each machine runs
its own Raft Ward gate before touching its local database; this SFTP packet
transport does not run a live remote app check. If a machine is offline, its
packet pickup waits. The planned standalone `kind = "rsync"` transport remains
unimplemented; use the configured rclone SFTP remote for SSH today.

If you use `rclone serve sftp` to expose a tree that a local Folder transport
also reads, start the server with `--dir-cache-time 0s`. Its default directory
cache can hide packets written locally for several minutes. Start it under a
private `umask 077`, then verify packet directories are `0700` and files are
`0600`. Folder transport refuses entries with broader permissions; fix the
test server's permissions before retrying pickup.

### Optional: Tailscale for SSH

For SSH, [Tailscale](https://tailscale.com/docs/install/linux)
can connect the two machines on a private network. Set up and verify SSH
separately; Tailscale reachability alone does not prove an app is closed or a
database is safe. The [Personal plan](https://tailscale.com/pricing) is free
for non-commercial home use under its current terms. Raft Ward's gates still
apply on both machines.

## Option C: a private shared folder or removable encrypted drive

Use this only when **both** machines already see the same securely shared
folder. The shared root must be owned by your user and mode `0700` on each
machine. A plain cloud-synced folder can expose chat contents; prefer an
encrypted drive or the rclone crypt option above. Do not use a OneDrive sync
mount as this folder. Configure the local path on each machine:

```toml
transport = { kind = "folder", path = "/path/to/private/shared/rafts" }
```

The folder carries packets, not live app data. Never point it at an app's
database directory. A disconnected or incompletely synced folder cannot prove
that a packet is ready; Raft Mover waits for a complete manifest and verifies
hashes and Raft Ward results before adoption.

Mover keeps unacknowledged packets. After a receiver applies one, it writes a
signed acknowledgment. `keep_last_n = 5` retains the newest acknowledged
packets for each raft; older acknowledged packets may be removed. This does
not remove local pre-adopt backups or legacy packets without a generation
number. Rclone uploads use an incomplete packet
directory, publish the manifest last, and remove old incomplete directories
only when the remote reports a reliable age of more than seven days.
A pickup that races an upload, or sees a fresh manifest-less packet folder,
reports `incomplete-packet` with exit code `3`. Retry after the upload finishes;
an abandoned incomplete folder is swept only after seven days.

## Optional idle app closing

Bare `move` asks you to close an owning app yourself. To opt into a polite
close, add the following to an app's private config, using its **exact main
Linux process name** as the first `processes` entry:

```toml
[apps.chat]
processes = ["chat", "chat-worker"]
quit = "signal:TERM"
exe = "/absolute/path/to/chat"
app_idle_minutes = 10
cpu_idle_pct = 3
busy_processes = ["chat-agent", "chat-shell"]
close_timeout_s = 90
```

`move --close` is experimental. It observes the app over the configured quiet
window before it sends SIGTERM to one verified main process through a Linux
pidfd. It checks the executable path, CPU,
listed busy workers, and database/WAL timestamps by **stat only**. If the app
does not exit by the timeout, that raft waits; Mover never sends SIGKILL.
Timer runs use `--auto` and also require the whole user to be idle. The current
Linux idle backend uses logind only. If the desktop does not publish logind's
idle hint, as on current COSMIC setups, the timer does nothing. Keep v0.1
supervised. Do not enable unattended closing until a supervised move and
return move, including your app's quit behavior, have passed independent
review. When the hint cannot be verified, `--auto` prints `idle-unknown` and
exits `4`. Electron crashpad helpers may make `--close` refuse as ambiguous;
AppImage and snap executable paths may prevent an exact `exe` match. The
`[apps.chat]` name and process names above are examples.

## First supervised move

1. Finish each machine's `move init` configuration and verify that matching
   raft labels refer to the intended local database paths.
2. Keep the owning apps closed on both machines. Run `move --dry-run` on the
   sender; it should name what is eligible without closing or moving anything.
3. Run `move` on the sender, then `move pickup` on the receiver. On a first
   pairing, the receiver stages the packet because there is no established
   common lineage. Review both local histories before explicitly using
   `move adopt RAFT-LABEL --keep-both`. The original is backed up. Check
   `move --status` on both. `--status` only reports; it never adopts a packet.
4. Create a harmless new chat on the receiver, close the app, and move it back.
   Confirm the new chat and its continuation on the first machine. Keep the
   pre-adopt backups until you are satisfied.
5. If histories differ, pickup reports `staged (diverged-or-unpaired)` and
   `move --status` reports `diverged`. Raft Mover will
   not merge or silently choose a winner. Review both copies before any manual
   `move adopt RAFT-LABEL --keep-both`.

Raft Ward can also be installed **by itself** for local, read-only checks. It
does not configure rclone or transfer a database.

## Checking and recovering a move

`move pickup --stage-only` verifies and stages packets without adopting them.
Set `stage_only = true` in the private config if that should be the default.
`move report --format json` gives a machine-readable local report; `text`,
`md`, and `html` are also available. `move --status` is read-only.

Mover keeps pre-adopt copies under its private state directory's `backups/`
folder. `move --status` and `move report` show each raft's backup count and
total bytes. For manual cleanup after both histories are settled, remove only
backups that are not named by any lineage `backup` or `diverged_backup` field
and not named by any pending receipt's `backup` field. Keep a verified archive
first if an older copy may still be needed.
`move restore RAFT-LABEL` verifies the recorded backup before replacing
the local database and keeps a copy of the current database first. Review both
histories before restoring. An interrupted move may report `pending`; a later
locked run checks that packet again. If it reports `pending-swap-ambiguous` or
`pending-backup-missing`, leave the database, staged packet, and backups in
place for supervised review. Do not delete the receipt or force an adoption.
After reviewing both histories, `move recover RAFT-LABEL --accept-current`
keeps and backs up the current local database and signs a declined acknowledgment
for the pending packet. It breaks automatic lineage and does not move or merge
either database. After the acknowledgment is confirmed, Mover removes the
declined staged copy. If the acknowledgment is unavailable, the stage waits for
a later retry or is removed after a newer packet is adopted. Use this only when
keeping the current copy is a deliberate manual choice.

Exit codes are `0` completed, `1` integrity or transport failure, `2` usage or
config error, `3` held for review, `4` check inconclusive, `130` Ctrl-C, and
`143` SIGTERM. A scheduled run must treat nonzero as no approval to move.
For a custom config, run `move --config /path/to/config.toml print-timer`; the
printed systemd and cron commands carry that same config path.
