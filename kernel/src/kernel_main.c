#include "kernel.h"

#define AEGIS_SCHEDULER_CAPACITY 64u

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
  for (i = 0; i < AEGIS_SCHEDULER_CAPACITY; ++i) {
    scheduler->process_ids[i] = 0;
    scheduler->priorities[i] = AEGIS_PRIORITY_NORMAL;
    scheduler->credits[i] = 0;
    scheduler->dispatch_counts[i] = 0;
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
  for (i = idx + 1; i < scheduler->count; ++i) {
    scheduler->process_ids[i - 1] = scheduler->process_ids[i];
    scheduler->priorities[i - 1] = scheduler->priorities[i];
    scheduler->credits[i - 1] = scheduler->credits[i];
    scheduler->dispatch_counts[i - 1] = scheduler->dispatch_counts[i];
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
    scheduler->dispatch_counts[idx] += 1;
    scheduler->total_dispatches += 1;
    scheduler->scheduler_ticks += 1;
    *process_id = scheduler->process_ids[idx];
    scheduler->head = (idx + 1) % scheduler->count;
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
  }
}
