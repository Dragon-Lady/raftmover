# Raft Mover 0.1.3 release notes

This release turns the Cursor worker owner exemption off by default, matching
Raft Ward 0.1.5. It requires Raft Ward 0.1.5 or later.

- `owner_exempt` now defaults to `[]`. Cursor's detached background agent
  worker (`cursor-agent ... worker start`) counts as an owner again, so it
  holds rafts as `owning-app-running` unless you opt in.
- To turn the exemption on, set `owner_exempt = ["cursor-agent-worker"]` in
  your config. Configs that already set the key keep their value. Configs
  that omitted it (the 0.1.2 implicit default) treat the worker as an owner
  after upgrading.
- An exempt worker is still checked by Raft Ward: if it has the database or
  a sidecar open, or matches a transfer check, the raft is held as before.

The supervised-operation guidance and limitations from 0.1.0 still apply.
Apps must be closed and Raft Ward checks must pass before a transfer proceeds.
