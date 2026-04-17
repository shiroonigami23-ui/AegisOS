# kernel

Kernel direction, interfaces, and implementation notes live here.

## Current Modules

- `aegis_vm_space_t`: virtual memory region mapping abstraction.
  - supports map/unmap/query with overlap/overflow guards.
  - supports exact-region permission flag updates and region split helper for pager preparation.
  - includes query lookup-cache fast path for repeated hot-address lookups.
  - exposes JSON summary endpoint for VM map observability.
- `aegis_ipc_envelope_t`: IPC channel envelope format helper.
  - supports fixed-size encode/decode and schema/payload validation checks.
  - includes payload-fit guard helper for max-frame enforcement.
- `aegis_scheduler_t`: weighted round-robin scheduler with priority-aware dispatch.
  - optimized hot-path dispatch bookkeeping with live `priority_counts` and `runnable_credit_count` counters to reduce full-queue scans.
  - adds admission/ready priority bitmaps for constant-time priority-class presence checks.
  - adds popcount-based single-runnable-class fastpath over ready bitmap to cut dispatch scans.
  - adds turbo candidate cache reuse to reduce full-score recomputation frequency.
  - includes adaptive quantum autotuner to rebalance tail-latency and context-switch pressure automatically.
  - includes optional `turbo` dispatch strategy that scores queue entries by priority + wait time for lower tail latency.
  - turbo mode retains fairness pressure by debiasing over-dispatched processes and preserving credit-based limits.
  - turbo mode includes adaptive weight autotuning to rebalance `priority` vs `wait` based on live latency telemetry.
  - low-priority aging boosts add temporary credits after long waits to reduce starvation risk.
  - includes dispatch metrics: total dispatches, high-watermark queue depth, and per-process counts.
  - tracks dispatch scan-depth telemetry (`calls`, `steps_total`, `max_steps`) for hot-path tuning.
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
  - wait-report percentile path now uses selection-based computation to reduce metrics overhead.
  - includes PID lookup-cache fast path for repeated scheduler control-plane queries.
  - PID lookup now uses dual-entry (primary + victim) cache with promotion for repeated churned PID access.
  - includes bulk scheduler operation API (`add/remove/reprioritize`) with execution telemetry counters.
  - turbo scheduler now adapts candidate cache reuse budget by queue pressure and switch patterns.
  - turbo scoring now penalizes runaway dispatch dominance to preserve fairness under heavy load.
  - wait-latency accounting includes safety clamps for non-monotonic tick edge cases.
  - includes wait-report snapshot endpoint with capture tick and queue metadata.
- `aegis_process_checkpoint_table_t`: process checkpoint capture/restore for recovery workflows.
  - supports process runtime registration and per-reason checkpoint capture.
  - supports checkpoint restore with epoch verification and failure counters.
  - includes runtime/checkpoint PID lookup-cache fast paths with hit/miss telemetry.
  - includes overwrite/query-miss/epoch-mismatch/replay-applied counters for recovery observability.
  - exposes snapshot JSON endpoint with entry-level checkpoint metadata.
  - supports disk-backed journal save and boot-time replay for crash recovery.
- `aegis_secure_time_attestor_t`:
  - includes nonce lookup-cache fast path for repeated nonce-replay checks.
  - tracks drift-budget clamp events and nonce cache hit/miss telemetry in snapshot JSON.
- `aegis_syscall_gate_matrix_t`: syscall capability enforcement matrix.
  - includes decision-cache fast path for hot process/syscall pairs.
  - includes process/rule lookup-cache fast paths to reduce repeated linear scans.
  - supports rule removal API with snapshot telemetry (`removed_rule_count`) for policy churn tracking.
  - preserves deny-reason counters while reducing repeated linear scans.
- `aegis_ipc_channel_table_t` and `aegis_memory_zone_table_t`:
  - include lookup-cache fast paths for hot channel/zone IDs.
  - expose lookup-cache hit/miss telemetry in JSON snapshots.
  - include IPC unknown-channel and drain-underflow clamp counters in snapshot telemetry.
  - include IPC drop-reason breakdown counters (`quota`, `unknown_channel`, `policy_gate`) for triage.
  - include IPC burst-budget autotune (quota up/down adjustments) based on sustained pressure/drain behavior.
  - include memory unknown-zone, release-underflow clamp, and reclaim-shortfall counters.
  - include per-zone reclaim efficiency telemetry (current + EMA) for reclaim policy tuning.
- `aegis_namespace_table_t`:
  - includes lookup-cache fast paths for local/global pid translation.
  - includes requester/target inspect-pair cache fastpath for repeated visibility checks.
  - exposes lookup-cache hit/miss telemetry in namespace snapshot JSON.
  - tracks attach/detach/translate/inspect failure counters for error-path observability.
  - tracks namespace cache invalidation count to expose mutation churn.

## Performance Governance

- cross-module hotpath benchmark source: `tools/benchmarks/kernel_hotpath_bench.c`
- local runner: `python scripts/kernel_hotpath_benchmark.py --iterations 200000`
- CI budget gate: `.github/workflows/perf-budget.yml` with thresholds in `docs/PERF_BUDGET.json`
- snapshot schema ledger: `docs/SNAPSHOT_SCHEMA_LEDGER.md` validated by `scripts/validate_snapshot_schema_ledger.py`
