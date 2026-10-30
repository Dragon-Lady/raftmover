# Raft Mover 0.1.2 release notes

This release lets moves go ahead while Cursor's background agent worker runs.
It requires Raft Ward 0.1.5 or later.

- Pass Raft Ward 0.1.5's fixed `cursor-agent-worker` owner exemption by
  default. Cursor's detached worker (`cursor-agent ... worker start`) no
  longer holds rafts as `owning-app-running`. The Cursor editor and every
  other `cursor-agent` command still do.
- An exempt worker is still checked by Raft Ward: if it has the database or
  a sidecar open, or matches a transfer check, the raft is held as before.
- Add the `owner_exempt` config setting. `["cursor-agent-worker"]` is the
  default and `[]` turns the exemption off. Any other value is a configuration
  error. `move init` writes the default into new starter configs.
- Require `raftward>=0.1.5,<0.2`, and make the runtime version check reject
  older Raft Ward builds, including 0.1.5 pre-releases.
- Document that a shell or wrapper whose command line mentions an app's
  process name counts as that app running.

The supervised-operation guidance and limitations from 0.1.0 still apply.
Apps must be closed and Raft Ward checks must pass before a transfer proceeds.
An inconclusive idle hint or ambiguous process identity still prevents a move.
