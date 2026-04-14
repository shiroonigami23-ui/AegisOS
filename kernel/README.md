# kernel

Kernel direction, interfaces, and implementation notes live here.

## Current Modules

- `aegis_vm_space_t`: virtual memory region mapping abstraction.
  - supports map/unmap/query with overlap/overflow guards.
  - supports exact-region permission flag updates and region split helper for pager preparation.
  - exposes JSON summary endpoint for VM map observability.
- `aegis_ipc_envelope_t`: IPC channel envelope format helper.
  - supports fixed-size encode/decode and schema/payload validation checks.
  - includes payload-fit guard helper for max-frame enforcement.
- `aegis_scheduler_t`: weighted round-robin scheduler with priority-aware dispatch.
  - optimized hot-path dispatch bookkeeping with live `priority_counts` and `runnable_credit_count` counters to reduce full-queue scans.
  - adds admission/ready priority bitmaps for constant-time priority-class presence checks.
  - adds turbo candidate cache reuse to reduce full-score recomputation frequency.
  - includes adaptive quantum autotuner to rebalance tail-latency and context-switch pressure automatically.
  - includes optional `turbo` dispatch strategy that scores queue entries by priority + wait time for lower tail latency.
  - turbo mode retains fairness pressure by debiasing over-dispatched processes and preserving credit-based limits.
  - turbo mode includes adaptive weight autotuning to rebalance `priority` vs `wait` based on live latency telemetry.
  - low-priority aging boosts add temporary credits after long waits to reduce starvation risk.
  - includes dispatch metrics: total dispatches, high-watermark queue depth, and per-process counts.
  - includes timer-tick preemption simulation hooks with configurable quantum.
  - context switches expose reason codes (`process_start`, `quantum_expired`, `process_exit`, `manual_yield`).
  - includes per-reason context-switch counters for metrics breakdowns and alerting.
  - includes structured metrics snapshot API for observability integration.
  - metrics snapshot now includes reason-count breakdown and a schema version tag.
  - metrics snapshot includes a rolling reason-histogram window (`last 32 switches`) for anomaly detection.
  - exposes custom-window histogram query API for caller-provided switch windows.
  - exposes custom-window histogram JSON endpoint for dashboards and automation consumers.
  - exposes fairness snapshot JSON endpoint with per-process dispatch share and wait metrics.
  - includes JSON serializers for metrics snapshots and wait-report snapshots.
  - includes tick-based wait-time and last-latency counters per process.
  - includes aggregate wait report (`mean`, `p95`, `max`) for tuning and diagnostics.
  - includes wait-report snapshot endpoint with capture tick and queue metadata.
- `aegis_process_checkpoint_table_t`: process checkpoint capture/restore for recovery workflows.
  - supports process runtime registration and per-reason checkpoint capture.
  - supports checkpoint restore with epoch verification and failure counters.
  - exposes snapshot JSON endpoint with entry-level checkpoint metadata.
  - supports disk-backed journal save and boot-time replay for crash recovery.
- `aegis_syscall_gate_matrix_t`: syscall capability enforcement matrix.
  - includes decision-cache fast path for hot process/syscall pairs.
  - preserves deny-reason counters while reducing repeated linear scans.
