# Capability Output Amendment

Date: 2026-08-14
Status: Approved by continuation of the full product implementation

## Problem

The original scanner-core API accepted arbitrary output paths and attempted to
publish, roll back, and delete artifacts at those paths. Security review proved
that a path-based rollback cannot both revoke a failed publication and preserve
an unrelated file swapped into the same name by a concurrent same-UID actor.

## Amended boundary

1. `scan_file` is a pure scanner boundary. It reads one verified source and
   returns a closed `ScanResult` plus an optional in-memory UTF-8 derivative.
   It never creates, replaces, renames, chmods, or deletes a caller path.
2. The CLI emits only the compact four-field result JSON on stdout. It may write
   a low-only derivative solely to an already-open file descriptor supplied by
   its parent process. It accepts no result or derivative pathname.
3. Persistent publication belongs to `JobStore`. The API creates a fresh opaque
   single-use job directory before the worker runs. The worker has a job-scoped
   directory capability and never publishes into an arbitrary caller path.
4. Job state is monotonic. The result file is the final commit record. A failed
   job publishes only quarantine; a derivative is readable only when the
   committed result is `low`.
5. No rollback operation removes or renames a pathname that could have been
   replaced by an untrusted concurrent actor. Failed private staging objects may
   be abandoned for narrow retention cleanup inside the opaque job directory.

This amendment removes the load-bearing path races found in scanner-core Task 5
instead of attempting another check-then-use patch.
