# Changelog

## 0.1.3 - 2026-11-18

### Changed

- The Cursor worker owner exemption is now off by default, matching Raft
  Ward 0.1.5. Anyone who wants it turns it on in config.
- Default `owner_exempt` to off (`[]`), matching Raft Ward. Cursor's detached
  background agent worker (`cursor-agent ... worker start`) now counts as an
  owner unless you opt in with `owner_exempt = ["cursor-agent-worker"]`.
  Existing configs that already set the key keep their value. Configs that
  omitted it (the 0.1.2 implicit default) treat the worker as an owner after
  upgrading.
