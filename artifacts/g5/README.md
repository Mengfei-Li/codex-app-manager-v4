# G5 acceptance evidence

The canonical G5 acceptance record is `g5-acceptance-2026-08-04.json`.
It binds the exact Manager commit to the successful GitHub Actions run, all
six required jobs, and the five immutable evidence archives. The archives were
downloaded, their GitHub-reported SHA-256 digests were independently checked,
and their embedded JSON contracts were inspected before this record was made.

The local `downloaded/` directory is an ignored verification cache. It is not
part of the durable evidence boundary; GitHub artifact IDs and digests are.
