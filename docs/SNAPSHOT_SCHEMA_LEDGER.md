# Snapshot Schema Ledger

This ledger is the compatibility source of truth for kernel snapshot JSON schema markers consumed by tooling and dashboards.

## Rules

- Snapshot schemas are versioned and never changed silently.
- Any schema bump requires updating this ledger and its validator inputs.
- Existing fields may be added in a backward-compatible way, but existing field semantics should not be repurposed.
- CI validates this ledger via `scripts/validate_snapshot_schema_ledger.py`.

## Current Ledger

Machine-readable source: [`docs/SNAPSHOT_SCHEMA_LEDGER.json`](SNAPSHOT_SCHEMA_LEDGER.json).

Tracked snapshot contracts currently include:

- VM summary snapshot (`schema_version: 1`)
- Scheduler turbo state snapshot (`schema_version: 1`)
- Scheduler quantum-autotune snapshot (`schema_version: 1`)
- Scheduler metrics snapshot constant (`AEGIS_SCHEDULER_SNAPSHOT_SCHEMA_VERSION = 2`)
- Scheduler metrics snapshot JSON serialization contract
- Scheduler histogram window snapshot (`schema_version: 1`)
- Scheduler fairness snapshot (`schema_version: 1`)
- Scheduler admission snapshot (`schema_version: 1`)
- Namespace snapshot (`schema_version: 1`)
- Syscall gate snapshot (`schema_version: 1`)
- IPC channel snapshot (`schema_version: 1`)
- Memory zone snapshot (`schema_version: 1`)
