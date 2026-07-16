# ShadowPipe Phase-3 final host verdict

- Overall verdict: **PASS**
- Guest matrix: valid
- macOS safety: valid
- Cleanup: valid
- Exact clone absence: valid
- Evidence seal: valid
- Release helper SHADOWPIPE_MAGIC: 0x50334852
- Release helper magic source: fixed_lab_default
- Loaded PF runtime observed: false
- Field evidence: false
- Host-safety scope: PF files and the exact stable permission-denied collector outcome were compared; loaded PF runtime rules were not observed.
- Host-safety timing: before/after endpoint snapshots, not a continuous mutation monitor.
- Evidence authenticity: relative SHA-256 plus a final census; no external signature or timestamp authority.
- VM identity: strict duplicate-key-rejecting OrbStack JSON bound opaque source/clone IDs; start/stop/guest operations used the clone ID, while delete-by-name required an immediate name-to-ID revalidation because OrbStack 2.2.1 panicked on delete-by-ID in an observed lab run.

An unrelated same-host OrbStack lifecycle operator is outside this run's trust boundary.
