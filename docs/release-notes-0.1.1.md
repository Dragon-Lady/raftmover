# Raft Mover 0.1.1 release notes

This maintenance release improves test isolation and release verification.
It does not enable automatic transfers or change the runtime safety gates.

- Use unique process-tree fixture names so leftovers from another test run
  cannot contaminate a later run.
- Freeze the idle-hint clock in its regression test, without requiring a
  long-lived login session.
- Build and scan wheels and source archives before PyPI upload. Release scans
  require an explicit private-term list and retain secret detection.
- Publish the scanned artifacts through Trusted Publishing with provenance
  attestations, and check the tag against the package version.

The supervised-operation guidance and limitations from 0.1.0 still apply.
Apps must be closed and Raft Ward checks must pass before a transfer proceeds.
An inconclusive idle hint or ambiguous process identity still prevents a move.
