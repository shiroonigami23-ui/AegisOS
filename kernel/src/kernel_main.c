#include "kernel.h"

#include <stdio.h>

#define AEGIS_SCHEDULER_CAPACITY 64u

static void sort_u64(uint64_t *arr, size_t n) {
  size_t i;
  size_t j;
  for (i = 0; i < n; ++i) {
    for (j = i + 1; j < n; ++j) {
      if (arr[j] < arr[i]) {
        uint64_t tmp = arr[i];
        arr[i] = arr[j];
        arr[j] = tmp;
      }
    }
  }
}

int aegis_kernel_boot_check(void) {
  return 0;
}

static uint8_t normalize_priority(uint8_t priority) {
  if (priority < AEGIS_PRIORITY_LOW || priority > AEGIS_PRIORITY_HIGH) {
    return AEGIS_PRIORITY_NORMAL;
  }
  return priority;
}

static void refill_credits(aegis_scheduler_t *scheduler) {
  size_t i;
  for (i = 0; i < scheduler->count; ++i) {
    scheduler->credits[i] = normalize_priority(scheduler->priorities[i]);
  }
}

void aegis_scheduler_init(aegis_scheduler_t *scheduler) {
  size_t i;
  if (scheduler == 0) {
    return;
  }
  scheduler->count = 0;
  scheduler->head = 0;
  scheduler->total_dispatches = 0;
  scheduler->scheduler_ticks = 0;
  scheduler->high_watermark = 0;
  scheduler->current_pid = 0;
  scheduler->pending_switch_reason = AEGIS_SWITCH_PROCESS_START;
  scheduler->quantum_ticks = 3;
  scheduler->quantum_remaining = 0;
  for (i = 0; i < AEGIS_SCHEDULER_CAPACITY; ++i) {
    scheduler->process_ids[i] = 0;
    scheduler->priorities[i] = AEGIS_PRIORITY_NORMAL;
    scheduler->credits[i] = 0;
    scheduler->dispatch_counts[i] = 0;
    scheduler->enqueued_tick[i] = 0;
    scheduler->wait_ticks_total[i] = 0;
    scheduler->last_wait_latency[i] = 0;
  }
  for (i = 0; i < 5u; ++i) {
    scheduler->reason_switch_counts[i] = 0;
  }
}

static int find_index(const aegis_scheduler_t *scheduler, uint32_t process_id, size_t *index) {
  size_t i;
  if (scheduler == 0 || index == 0 || process_id == 0) {
    return 0;
  }
  for (i = 0; i < scheduler->count; ++i) {
    if (scheduler->process_ids[i] == process_id) {
      *index = i;
      return 1;
    }
  }
  return 0;
}

int aegis_scheduler_add(aegis_scheduler_t *scheduler, uint32_t process_id) {
  return aegis_scheduler_add_with_priority(scheduler, process_id, AEGIS_PRIORITY_NORMAL);
}

int aegis_scheduler_add_with_priority(aegis_scheduler_t *scheduler, uint32_t process_id,
                                      uint8_t priority) {
  size_t existing = 0;
  if (scheduler == 0 || process_id == 0) {
    return -1;
  }
  if (scheduler->count >= AEGIS_SCHEDULER_CAPACITY) {
    return -1;
  }
  if (find_index(scheduler, process_id, &existing)) {
    return -1;
  }
  scheduler->process_ids[scheduler->count] = process_id;
  scheduler->priorities[scheduler->count] = normalize_priority(priority);
  scheduler->credits[scheduler->count] = scheduler->priorities[scheduler->count];
  scheduler->dispatch_counts[scheduler->count] = 0;
  scheduler->enqueued_tick[scheduler->count] = scheduler->scheduler_ticks;
  scheduler->wait_ticks_total[scheduler->count] = 0;
  scheduler->last_wait_latency[scheduler->count] = 0;
  scheduler->count += 1;
  if (scheduler->count > scheduler->high_watermark) {
    scheduler->high_watermark = scheduler->count;
  }
  return 0;
}

int aegis_scheduler_remove(aegis_scheduler_t *scheduler, uint32_t process_id) {
  size_t idx = 0;
  size_t i;
  if (!find_index(scheduler, process_id, &idx)) {
    return -1;
  }
  if (scheduler->current_pid == process_id) {
    scheduler->current_pid = 0;
    scheduler->quantum_remaining = 0;
    scheduler->pending_switch_reason = AEGIS_SWITCH_PROCESS_EXIT;
  }
  for (i = idx + 1; i < scheduler->count; ++i) {
    scheduler->process_ids[i - 1] = scheduler->process_ids[i];
    scheduler->priorities[i - 1] = scheduler->priorities[i];
    scheduler->credits[i - 1] = scheduler->credits[i];
    scheduler->dispatch_counts[i - 1] = scheduler->dispatch_counts[i];
    scheduler->enqueued_tick[i - 1] = scheduler->enqueued_tick[i];
    scheduler->wait_ticks_total[i - 1] = scheduler->wait_ticks_total[i];
    scheduler->last_wait_latency[i - 1] = scheduler->last_wait_latency[i];
  }
  scheduler->count -= 1;
  if (scheduler->count == 0) {
    scheduler->head = 0;
    return 0;
  }
  if (idx < scheduler->head && scheduler->head > 0) {
    scheduler->head -= 1;
  } else if (scheduler->head >= scheduler->count) {
    scheduler->head = 0;
  }
  return 0;
}

int aegis_scheduler_set_priority(aegis_scheduler_t *scheduler, uint32_t process_id, uint8_t priority) {
  size_t idx = 0;
  if (scheduler == 0 || !find_index(scheduler, process_id, &idx)) {
    return -1;
  }
  scheduler->priorities[idx] = normalize_priority(priority);
  scheduler->credits[idx] = scheduler->priorities[idx];
  return 0;
}

int aegis_scheduler_next(aegis_scheduler_t *scheduler, uint32_t *process_id) {
  size_t attempts;
  int any_credit = 0;
  size_t i;
  if (scheduler == 0 || process_id == 0 || scheduler->count == 0) {
    return -1;
  }
  for (i = 0; i < scheduler->count; ++i) {
    if (scheduler->credits[i] > 0) {
      any_credit = 1;
      break;
    }
  }
  if (!any_credit) {
    refill_credits(scheduler);
  }
  for (attempts = 0; attempts < scheduler->count; ++attempts) {
    size_t idx = (scheduler->head + attempts) % scheduler->count;
    if (scheduler->credits[idx] == 0) {
      continue;
    }
    scheduler->credits[idx] -= 1;
    scheduler->last_wait_latency[idx] = scheduler->scheduler_ticks - scheduler->enqueued_tick[idx];
    scheduler->wait_ticks_total[idx] += scheduler->last_wait_latency[idx];
    scheduler->dispatch_counts[idx] += 1;
    scheduler->total_dispatches += 1;
    *process_id = scheduler->process_ids[idx];
    scheduler->head = (idx + 1) % scheduler->count;
    scheduler->enqueued_tick[idx] = scheduler->scheduler_ticks;
    return 0;
  }
  return -1;
}

size_t aegis_scheduler_count(const aegis_scheduler_t *scheduler) {
  if (scheduler == 0) {
    return 0;
  }
  return scheduler->count;
}

uint64_t aegis_scheduler_total_dispatches(const aegis_scheduler_t *scheduler) {
  if (scheduler == 0) {
    return 0;
  }
  return scheduler->total_dispatches;
}

size_t aegis_scheduler_high_watermark(const aegis_scheduler_t *scheduler) {
  if (scheduler == 0) {
    return 0;
  }
  return scheduler->high_watermark;
}

int aegis_scheduler_dispatch_count_for(const aegis_scheduler_t *scheduler, uint32_t process_id,
                                       uint32_t *dispatch_count) {
  size_t idx = 0;
  if (dispatch_count == 0 || scheduler == 0 || !find_index(scheduler, process_id, &idx)) {
    return -1;
  }
  *dispatch_count = scheduler->dispatch_counts[idx];
  return 0;
}

void aegis_scheduler_reset_metrics(aegis_scheduler_t *scheduler) {
  size_t i;
  if (scheduler == 0) {
    return;
  }
  scheduler->total_dispatches = 0;
  scheduler->scheduler_ticks = 0;
  for (i = 0; i < scheduler->count; ++i) {
    scheduler->dispatch_counts[i] = 0;
    scheduler->wait_ticks_total[i] = 0;
    scheduler->last_wait_latency[i] = 0;
    scheduler->enqueued_tick[i] = scheduler->scheduler_ticks;
  }
  for (i = 0; i < 5u; ++i) {
    scheduler->reason_switch_counts[i] = 0;
  }
}

void aegis_scheduler_set_quantum(aegis_scheduler_t *scheduler, uint32_t quantum_ticks) {
  if (scheduler == 0 || quantum_ticks == 0) {
    return;
  }
  scheduler->quantum_ticks = quantum_ticks;
  if (scheduler->quantum_remaining > quantum_ticks) {
    scheduler->quantum_remaining = quantum_ticks;
  }
}

int aegis_scheduler_on_tick(aegis_scheduler_t *scheduler, uint32_t *running_pid,
                            uint8_t *context_switch) {
  uint8_t reason = AEGIS_SWITCH_NONE;
  return aegis_scheduler_on_tick_ex(scheduler, running_pid, context_switch, &reason);
}

int aegis_scheduler_on_tick_ex(aegis_scheduler_t *scheduler, uint32_t *running_pid,
                               uint8_t *context_switch, uint8_t *switch_reason) {
  uint32_t next_pid = 0;
  int rc;
  if (scheduler == 0 || running_pid == 0 || context_switch == 0 || switch_reason == 0) {
    return -1;
  }
  *context_switch = 0;
  *switch_reason = AEGIS_SWITCH_NONE;
  scheduler->scheduler_ticks += 1;
  if (scheduler->count == 0) {
    scheduler->current_pid = 0;
    scheduler->quantum_remaining = 0;
    scheduler->pending_switch_reason = AEGIS_SWITCH_PROCESS_START;
    *running_pid = 0;
    return 0;
  }
  if (scheduler->current_pid == 0 || scheduler->quantum_remaining == 0) {
    uint8_t reason = scheduler->pending_switch_reason;
    if (reason == AEGIS_SWITCH_NONE) {
      reason = AEGIS_SWITCH_QUANTUM_EXPIRED;
    }
    rc = aegis_scheduler_next(scheduler, &next_pid);
    if (rc != 0) {
      return -1;
    }
    *context_switch = 1;
    *switch_reason = reason;
    if (reason <= AEGIS_SWITCH_MANUAL_YIELD) {
      scheduler->reason_switch_counts[reason] += 1;
    }
    scheduler->current_pid = next_pid;
    scheduler->quantum_remaining = scheduler->quantum_ticks;
    scheduler->pending_switch_reason = AEGIS_SWITCH_NONE;
  }
  if (scheduler->quantum_remaining > 0) {
    scheduler->quantum_remaining -= 1;
    if (scheduler->quantum_remaining == 0 && scheduler->count > 0) {
      scheduler->pending_switch_reason = AEGIS_SWITCH_QUANTUM_EXPIRED;
    }
  }
  *running_pid = scheduler->current_pid;
  return 0;
}

int aegis_scheduler_manual_yield(aegis_scheduler_t *scheduler) {
  if (scheduler == 0 || scheduler->count == 0) {
    return -1;
  }
  scheduler->quantum_remaining = 0;
  scheduler->pending_switch_reason = AEGIS_SWITCH_MANUAL_YIELD;
  return 0;
}

int aegis_scheduler_metrics_snapshot(const aegis_scheduler_t *scheduler,
                                     aegis_scheduler_metrics_snapshot_t *snapshot) {
  if (scheduler == 0 || snapshot == 0) {
    return -1;
  }
  snapshot->queue_depth = scheduler->count;
  snapshot->high_watermark = scheduler->high_watermark;
  snapshot->total_dispatches = scheduler->total_dispatches;
  snapshot->scheduler_ticks = scheduler->scheduler_ticks;
  snapshot->current_pid = scheduler->current_pid;
  snapshot->quantum_ticks = scheduler->quantum_ticks;
  snapshot->quantum_remaining = scheduler->quantum_remaining;
  return 0;
}

int aegis_scheduler_metrics_snapshot_json(const aegis_scheduler_metrics_snapshot_t *snapshot,
                                          char *out, size_t out_size) {
  int written;
  if (snapshot == 0 || out == 0 || out_size == 0u) {
    return -1;
  }
  written = snprintf(out, out_size,
                     "{\"queue_depth\":%llu,\"high_watermark\":%llu,\"total_dispatches\":%llu,"
                     "\"scheduler_ticks\":%llu,\"current_pid\":%u,\"quantum_ticks\":%u,"
                     "\"quantum_remaining\":%u}",
                     (unsigned long long)snapshot->queue_depth,
                     (unsigned long long)snapshot->high_watermark,
                     (unsigned long long)snapshot->total_dispatches,
                     (unsigned long long)snapshot->scheduler_ticks, snapshot->current_pid,
                     snapshot->quantum_ticks, snapshot->quantum_remaining);
  if (written < 0 || (size_t)written >= out_size) {
    return -1;
  }
  return written;
}

int aegis_scheduler_wait_ticks_for(const aegis_scheduler_t *scheduler, uint32_t process_id,
                                   uint64_t *wait_ticks) {
  size_t idx = 0;
  if (wait_ticks == 0 || scheduler == 0 || !find_index(scheduler, process_id, &idx)) {
    return -1;
  }
  *wait_ticks = scheduler->wait_ticks_total[idx];
  return 0;
}

int aegis_scheduler_last_latency_for(const aegis_scheduler_t *scheduler, uint32_t process_id,
                                     uint64_t *latency_ticks) {
  size_t idx = 0;
  if (latency_ticks == 0 || scheduler == 0 || !find_index(scheduler, process_id, &idx)) {
    return -1;
  }
  *latency_ticks = scheduler->last_wait_latency[idx];
  return 0;
}

int aegis_scheduler_wait_report(const aegis_scheduler_t *scheduler,
                                aegis_scheduler_wait_report_t *report) {
  uint64_t waits[AEGIS_SCHEDULER_CAPACITY];
  uint64_t lats[AEGIS_SCHEDULER_CAPACITY];
  uint64_t sum_wait = 0;
  uint64_t sum_lat = 0;
  size_t i;
  size_t n;
  size_t p95_index;
  if (scheduler == 0 || report == 0) {
    return -1;
  }
  n = scheduler->count;
  report->mean_wait_ticks = 0;
  report->p95_wait_ticks = 0;
  report->max_wait_ticks = 0;
  report->mean_last_latency_ticks = 0;
  report->p95_last_latency_ticks = 0;
  report->max_last_latency_ticks = 0;
  if (n == 0) {
    return 0;
  }
  for (i = 0; i < n; ++i) {
    waits[i] = scheduler->wait_ticks_total[i];
    lats[i] = scheduler->last_wait_latency[i];
    sum_wait += waits[i];
    sum_lat += lats[i];
  }
  sort_u64(waits, n);
  sort_u64(lats, n);
  p95_index = (n * 95u) / 100u;
  if (p95_index >= n) {
    p95_index = n - 1;
  }
  report->mean_wait_ticks = sum_wait / n;
  report->p95_wait_ticks = waits[p95_index];
  report->max_wait_ticks = waits[n - 1];
  report->mean_last_latency_ticks = sum_lat / n;
  report->p95_last_latency_ticks = lats[p95_index];
  report->max_last_latency_ticks = lats[n - 1];
  return 0;
}

int aegis_scheduler_wait_report_snapshot(const aegis_scheduler_t *scheduler,
                                         aegis_scheduler_wait_report_snapshot_t *snapshot) {
  if (scheduler == 0 || snapshot == 0) {
    return -1;
  }
  snapshot->captured_at_tick = scheduler->scheduler_ticks;
  snapshot->queue_depth = scheduler->count;
  snapshot->total_dispatches = scheduler->total_dispatches;
  return aegis_scheduler_wait_report(scheduler, &snapshot->report);
}

int aegis_scheduler_wait_report_snapshot_json(const aegis_scheduler_wait_report_snapshot_t *snapshot,
                                              char *out, size_t out_size) {
  int written;
  if (snapshot == 0 || out == 0 || out_size == 0u) {
    return -1;
  }
  written = snprintf(out, out_size,
                     "{\"captured_at_tick\":%llu,\"queue_depth\":%llu,\"total_dispatches\":%llu,"
                     "\"mean_wait_ticks\":%llu,\"p95_wait_ticks\":%llu,\"max_wait_ticks\":%llu,"
                     "\"mean_last_latency_ticks\":%llu,\"p95_last_latency_ticks\":%llu,"
                     "\"max_last_latency_ticks\":%llu}",
                     (unsigned long long)snapshot->captured_at_tick,
                     (unsigned long long)snapshot->queue_depth,
                     (unsigned long long)snapshot->total_dispatches,
                     (unsigned long long)snapshot->report.mean_wait_ticks,
                     (unsigned long long)snapshot->report.p95_wait_ticks,
                     (unsigned long long)snapshot->report.max_wait_ticks,
                     (unsigned long long)snapshot->report.mean_last_latency_ticks,
                     (unsigned long long)snapshot->report.p95_last_latency_ticks,
                     (unsigned long long)snapshot->report.max_last_latency_ticks);
  if (written < 0 || (size_t)written >= out_size) {
    return -1;
  }
  return written;
}

int aegis_scheduler_switch_reason_count(const aegis_scheduler_t *scheduler, uint8_t switch_reason,
                                        uint64_t *count) {
  if (scheduler == 0 || count == 0 || switch_reason > AEGIS_SWITCH_MANUAL_YIELD) {
    return -1;
  }
  *count = scheduler->reason_switch_counts[switch_reason];
  return 0;
}
