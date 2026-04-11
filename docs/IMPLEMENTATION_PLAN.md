# Implementation Plan (v0)

## Epic 1: Boot + Kernel Base

- Process model and scheduler skeleton.
- Scheduler admission control and queue pressure guardrails.
- Process namespace isolation and PID remap simulator.
- Virtual memory abstraction.
- IPC channel contract and message format.
- IPC channel quotas, backpressure, and per-channel accounting.
- Memory zone budgets, reclaim hooks, and low-memory pressure telemetry.

## Epic 2: Security Core

- Capability token lifecycle.
- Sandbox policy schema and evaluator.
- Secrets and key storage service.
- Syscall-to-capability gate matrix and enforcement counters.
- Telemetry privacy redaction rules for logs, metrics, and trace exports.
- Permission center policy diff and policy-change audit export.

## Epic 3: Package + Update System

- Package format and metadata validation.
- Delta update payload metadata schema + fallback digest validation.
- Atomic update transaction engine.
- Rollback index monotonic guard and downgrade prevention.
- Signed repository index and trust policy.
- Release channel pinning policy and transition rejection paths.

## Epic 4: UX + Device Profiles

- Desktop compositor prototype.
- Settings and permission center.
- Profile tuning for low-resource hardware.
- Boot budget enforcement reports per profile (cold/warm).
- Installer bootstrap state machine with attestation and recovery hooks.

## Epic 5: Compatibility

- Runtime boundary model.
- App ABI gateway and syscall mediation.
- Observability for compatibility failures.
- Runtime syscall allowlist scaffold with violation logs and summaries.
