# Raft Mover 0.1.0 release notes

Raft Mover 0.1.0 is a supervised Linux handoff for closed SQLite databases.
Every send and adoption requires Raft Ward checks, and incoming packets are
authenticated before use. Review the first pairing and any diverged history
before choosing a staged packet.

The timer uses logind's idle hint only. On COSMIC setups that do not publish the
hint, `--auto` prints `idle-unknown`, exits `4`, and makes no move. Use manual
`move` and `move pickup` for supervised operation.

`move --close` is experimental. It signals one verified main process only and
refuses uncertain process trees. Electron crashpad helpers may cause that
refusal; AppImage or snap executable paths may also prevent an exact match.
Closing the owning app manually is supported.

The package requires Raft Ward 0.1.4 or later within the 0.1 series. That
version corrects its reported runtime version. No data format or gate behavior
change is required for the correction.
