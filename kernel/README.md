# kernel

Kernel direction, interfaces, and implementation notes live here.

## Current Modules

- `aegis_scheduler_t`: weighted round-robin scheduler with priority-aware dispatch.
  - includes dispatch metrics: total dispatches, high-watermark queue depth, and per-process counts.
  - includes timer-tick preemption simulation hooks with configurable quantum.
  - context switches expose reason codes (`process_start`, `quantum_expired`, `process_exit`, `manual_yield`).
  - includes per-reason context-switch counters for metrics breakdowns and alerting.
  - includes structured metrics snapshot API for observability integration.
  - metrics snapshot now includes reason-count breakdown and a schema version tag.
  - includes JSON serializers for metrics snapshots and wait-report snapshots.
  - includes tick-based wait-time and last-latency counters per process.
  - includes aggregate wait report (`mean`, `p95`, `max`) for tuning and diagnostics.
  - includes wait-report snapshot endpoint with capture tick and queue metadata.
