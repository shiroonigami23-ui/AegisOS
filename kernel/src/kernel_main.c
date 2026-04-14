#include "kernel.h"

#include <stdio.h>
#include <string.h>

#define AEGIS_SCHEDULER_CAPACITY 64u
#define AEGIS_AGING_TICKS_PER_BOOST 5u
#define AEGIS_AGING_MAX_BOOST 2u

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

static int vm_region_valid(uint64_t base, uint64_t size) {
  if (size == 0u) {
    return 0;
  }
  if (base > UINT64_MAX - size) {
    return 0;
  }
  return 1;
}

static int vm_region_overlaps(uint64_t a_base, uint64_t a_size, uint64_t b_base, uint64_t b_size) {
  uint64_t a_end;
  uint64_t b_end;
  if (!vm_region_valid(a_base, a_size) || !vm_region_valid(b_base, b_size)) {
    return 0;
  }
  a_end = a_base + a_size;
  b_end = b_base + b_size;
  if (a_end <= b_base || b_end <= a_base) {
    return 0;
  }
  return 1;
}

int aegis_ipc_envelope_validate(const aegis_ipc_envelope_t *envelope, uint32_t max_payload_size) {
  if (envelope == 0) {
    return -1;
  }
  if (envelope->schema_version != AEGIS_IPC_ENVELOPE_SCHEMA_VERSION) {
    return -1;
  }
  if (envelope->message_type == 0u) {
    return -1;
  }
  if (envelope->payload_size > max_payload_size) {
    return -1;
  }
  return 0;
}

int aegis_ipc_envelope_payload_fits(const aegis_ipc_envelope_t *envelope,
                                    uint32_t max_frame_size,
                                    uint32_t *remaining_bytes) {
  uint32_t total_size;
  if (envelope == 0 || max_frame_size < 16u) {
    return -1;
  }
  if (envelope->payload_size > UINT32_MAX - 16u) {
    return -1;
  }
  total_size = 16u + envelope->payload_size;
  if (total_size > max_frame_size) {
    if (remaining_bytes != 0) {
      *remaining_bytes = 0u;
    }
    return 0;
  }
  if (remaining_bytes != 0) {
    *remaining_bytes = max_frame_size - total_size;
  }
  return 1;
}

int aegis_ipc_envelope_encode(const aegis_ipc_envelope_t *envelope, uint8_t *out, size_t out_size) {
  if (envelope == 0 || out == 0 || out_size < 16u) {
    return -1;
  }
  out[0] = (uint8_t)(envelope->schema_version & 0xFFu);
  out[1] = (uint8_t)((envelope->schema_version >> 8) & 0xFFu);
  out[2] = (uint8_t)(envelope->message_type & 0xFFu);
  out[3] = (uint8_t)((envelope->message_type >> 8) & 0xFFu);
  out[4] = (uint8_t)(envelope->flags & 0xFFu);
  out[5] = (uint8_t)((envelope->flags >> 8) & 0xFFu);
  out[6] = (uint8_t)((envelope->flags >> 16) & 0xFFu);
  out[7] = (uint8_t)((envelope->flags >> 24) & 0xFFu);
  out[8] = (uint8_t)(envelope->payload_size & 0xFFu);
  out[9] = (uint8_t)((envelope->payload_size >> 8) & 0xFFu);
  out[10] = (uint8_t)((envelope->payload_size >> 16) & 0xFFu);
  out[11] = (uint8_t)((envelope->payload_size >> 24) & 0xFFu);
  out[12] = (uint8_t)(envelope->correlation_id & 0xFFu);
  out[13] = (uint8_t)((envelope->correlation_id >> 8) & 0xFFu);
  out[14] = (uint8_t)((envelope->correlation_id >> 16) & 0xFFu);
  out[15] = (uint8_t)((envelope->correlation_id >> 24) & 0xFFu);
  return 16;
}

int aegis_ipc_envelope_decode(const uint8_t *in, size_t in_size, aegis_ipc_envelope_t *envelope) {
  if (in == 0 || envelope == 0 || in_size < 16u) {
    return -1;
  }
  envelope->schema_version = (uint16_t)(in[0] | ((uint16_t)in[1] << 8));
  envelope->message_type = (uint16_t)(in[2] | ((uint16_t)in[3] << 8));
  envelope->flags = (uint32_t)in[4] | ((uint32_t)in[5] << 8) | ((uint32_t)in[6] << 16) |
                    ((uint32_t)in[7] << 24);
  envelope->payload_size = (uint32_t)in[8] | ((uint32_t)in[9] << 8) | ((uint32_t)in[10] << 16) |
                           ((uint32_t)in[11] << 24);
  envelope->correlation_id = (uint32_t)in[12] | ((uint32_t)in[13] << 8) |
                             ((uint32_t)in[14] << 16) | ((uint32_t)in[15] << 24);
  return 0;
}

void aegis_vm_space_init(aegis_vm_space_t *space) {
  size_t i;
  if (space == 0) {
    return;
  }
  space->count = 0u;
  for (i = 0; i < AEGIS_VM_REGION_CAPACITY; ++i) {
    space->regions[i].base = 0u;
    space->regions[i].size = 0u;
    space->regions[i].flags = 0u;
    space->regions[i].active = 0u;
  }
}

int aegis_vm_map(aegis_vm_space_t *space, uint64_t base, uint64_t size, uint32_t flags) {
  size_t i;
  if (space == 0 || !vm_region_valid(base, size)) {
    return -1;
  }
  if (space->count >= AEGIS_VM_REGION_CAPACITY) {
    return -1;
  }
  for (i = 0; i < AEGIS_VM_REGION_CAPACITY; ++i) {
    aegis_vm_region_t *region = &space->regions[i];
    if (region->active == 0u) {
      continue;
    }
    if (vm_region_overlaps(base, size, region->base, region->size)) {
      return -1;
    }
  }
  for (i = 0; i < AEGIS_VM_REGION_CAPACITY; ++i) {
    aegis_vm_region_t *region = &space->regions[i];
    if (region->active != 0u) {
      continue;
    }
    region->base = base;
    region->size = size;
    region->flags = flags;
    region->active = 1u;
    space->count += 1u;
    return 0;
  }
  return -1;
}

int aegis_vm_unmap(aegis_vm_space_t *space, uint64_t base, uint64_t size) {
  size_t i;
  if (space == 0 || !vm_region_valid(base, size)) {
    return -1;
  }
  for (i = 0; i < AEGIS_VM_REGION_CAPACITY; ++i) {
    aegis_vm_region_t *region = &space->regions[i];
    if (region->active == 0u) {
      continue;
    }
    if (region->base == base && region->size == size) {
      region->active = 0u;
      region->base = 0u;
      region->size = 0u;
      region->flags = 0u;
      if (space->count > 0u) {
        space->count -= 1u;
      }
      return 0;
    }
  }
  return -1;
}

int aegis_vm_update_flags(aegis_vm_space_t *space, uint64_t base, uint64_t size, uint32_t flags) {
  size_t i;
  if (space == 0 || !vm_region_valid(base, size)) {
    return -1;
  }
  for (i = 0; i < AEGIS_VM_REGION_CAPACITY; ++i) {
    aegis_vm_region_t *region = &space->regions[i];
    if (region->active == 0u) {
      continue;
    }
    if (region->base == base && region->size == size) {
      region->flags = flags;
      return 0;
    }
  }
  return -1;
}

int aegis_vm_split_region(aegis_vm_space_t *space,
                          uint64_t base,
                          uint64_t size,
                          uint64_t split_offset) {
  size_t i;
  size_t target_index = AEGIS_VM_REGION_CAPACITY;
  size_t free_index = AEGIS_VM_REGION_CAPACITY;
  if (space == 0 || !vm_region_valid(base, size) || split_offset == 0u || split_offset >= size) {
    return -1;
  }
  if (space->count >= AEGIS_VM_REGION_CAPACITY) {
    return -1;
  }
  for (i = 0; i < AEGIS_VM_REGION_CAPACITY; ++i) {
    if (space->regions[i].active == 0u && free_index == AEGIS_VM_REGION_CAPACITY) {
      free_index = i;
    } else if (space->regions[i].active != 0u && space->regions[i].base == base &&
               space->regions[i].size == size) {
      target_index = i;
    }
  }
  if (target_index == AEGIS_VM_REGION_CAPACITY || free_index == AEGIS_VM_REGION_CAPACITY) {
    return -1;
  }
  {
    uint64_t second_base = base + split_offset;
    uint64_t second_size = size - split_offset;
    if (!vm_region_valid(second_base, second_size)) {
      return -1;
    }
    space->regions[target_index].size = split_offset;
    space->regions[free_index].base = second_base;
    space->regions[free_index].size = second_size;
    space->regions[free_index].flags = space->regions[target_index].flags;
    space->regions[free_index].active = 1u;
    space->count += 1u;
    return 0;
  }
}

int aegis_vm_query(const aegis_vm_space_t *space, uint64_t address, aegis_vm_region_t *region) {
  size_t i;
  if (space == 0 || region == 0) {
    return -1;
  }
  for (i = 0; i < AEGIS_VM_REGION_CAPACITY; ++i) {
    const aegis_vm_region_t *entry = &space->regions[i];
    if (entry->active == 0u) {
      continue;
    }
    if (address >= entry->base && address < (entry->base + entry->size)) {
      *region = *entry;
      return 0;
    }
  }
  return -1;
}

int aegis_vm_summary_json(const aegis_vm_space_t *space, char *out, size_t out_size) {
  size_t offset = 0;
  size_t i;
  int first = 1;
  int written;
  if (space == 0 || out == 0 || out_size == 0u) {
    return -1;
  }
  written = snprintf(out,
                     out_size,
                     "{\"schema_version\":1,\"region_count\":%llu,\"regions\":[",
                     (unsigned long long)space->count);
  if (written < 0 || (size_t)written >= out_size) {
    return -1;
  }
  offset = (size_t)written;
  for (i = 0; i < AEGIS_VM_REGION_CAPACITY; ++i) {
    const aegis_vm_region_t *region = &space->regions[i];
    if (region->active == 0u) {
      continue;
    }
    written = snprintf(out + offset,
                       out_size - offset,
                       "%s{\"base\":%llu,\"size\":%llu,\"flags\":%u}",
                       first ? "" : ",",
                       (unsigned long long)region->base,
                       (unsigned long long)region->size,
                       region->flags);
    if (written < 0 || (size_t)written >= (out_size - offset)) {
      return -1;
    }
    offset += (size_t)written;
    first = 0;
  }
  written = snprintf(out + offset, out_size - offset, "]}");
  if (written < 0 || (size_t)written >= (out_size - offset)) {
    return -1;
  }
  offset += (size_t)written;
  return (int)offset;
}

static uint8_t normalize_priority(uint8_t priority) {
  if (priority < AEGIS_PRIORITY_LOW || priority > AEGIS_PRIORITY_HIGH) {
    return AEGIS_PRIORITY_NORMAL;
  }
  return priority;
}

static int priority_bucket_index(uint8_t priority) {
  if (priority < AEGIS_PRIORITY_LOW || priority > AEGIS_PRIORITY_HIGH) {
    return -1;
  }
  return (int)priority;
}

static uint8_t priority_bucket_bit(uint8_t priority) {
  int bucket = priority_bucket_index(priority);
  if (bucket < 0) {
    return 0u;
  }
  return (uint8_t)(1u << (uint8_t)bucket);
}

static void scheduler_set_priority_present(aegis_scheduler_t *scheduler, uint8_t priority, uint8_t present) {
  uint8_t bit;
  if (scheduler == 0) {
    return;
  }
  bit = priority_bucket_bit(priority);
  if (bit == 0u) {
    return;
  }
  if (present != 0u) {
    scheduler->priority_present_bitmap |= bit;
  } else {
    scheduler->priority_present_bitmap = (uint8_t)(scheduler->priority_present_bitmap & (uint8_t)(~bit));
  }
}

static void scheduler_set_runnable_present(aegis_scheduler_t *scheduler, uint8_t priority, uint8_t present) {
  uint8_t bit;
  if (scheduler == 0) {
    return;
  }
  bit = priority_bucket_bit(priority);
  if (bit == 0u) {
    return;
  }
  if (present != 0u) {
    scheduler->runnable_priority_bitmap |= bit;
  } else {
    scheduler->runnable_priority_bitmap =
        (uint8_t)(scheduler->runnable_priority_bitmap & (uint8_t)(~bit));
  }
}

static void scheduler_runnable_credit_inc(aegis_scheduler_t *scheduler, uint8_t priority) {
  int bucket;
  if (scheduler == 0) {
    return;
  }
  bucket = priority_bucket_index(priority);
  if (bucket < 0) {
    return;
  }
  scheduler->runnable_priority_counts[(size_t)bucket] += 1u;
  scheduler->runnable_credit_count += 1u;
  scheduler_set_runnable_present(scheduler, priority, 1u);
}

static void scheduler_runnable_credit_dec(aegis_scheduler_t *scheduler, uint8_t priority) {
  int bucket;
  if (scheduler == 0) {
    return;
  }
  bucket = priority_bucket_index(priority);
  if (bucket < 0) {
    return;
  }
  if (scheduler->runnable_priority_counts[(size_t)bucket] > 0u) {
    scheduler->runnable_priority_counts[(size_t)bucket] -= 1u;
  }
  if (scheduler->runnable_credit_count > 0u) {
    scheduler->runnable_credit_count -= 1u;
  }
  if (scheduler->runnable_priority_counts[(size_t)bucket] == 0u) {
    scheduler_set_runnable_present(scheduler, priority, 0u);
  }
}

static uint8_t scheduler_priority_member_count(const aegis_scheduler_t *scheduler, uint8_t priority) {
  int bucket;
  if (scheduler == 0) {
    return 0u;
  }
  bucket = priority_bucket_index(priority);
  if (bucket < 0) {
    return 0u;
  }
  return scheduler->priority_counts[(size_t)bucket];
}

static void refill_credits(aegis_scheduler_t *scheduler) {
  size_t i;
  size_t b;
  scheduler->runnable_credit_count = 0u;
  scheduler->runnable_priority_bitmap = 0u;
  for (b = 0u; b < 4u; ++b) {
    scheduler->runnable_priority_counts[b] = 0u;
  }
  for (i = 0; i < scheduler->count; ++i) {
    uint8_t base = normalize_priority(scheduler->priorities[i]);
    /* Aging boost helps long-waiting low-priority tasks avoid starvation. */
    if (base == AEGIS_PRIORITY_LOW && AEGIS_AGING_TICKS_PER_BOOST > 0u) {
      uint64_t waited_ticks = scheduler->scheduler_ticks - scheduler->enqueued_tick[i];
      uint8_t boost = (uint8_t)(waited_ticks / AEGIS_AGING_TICKS_PER_BOOST);
      if (boost > AEGIS_AGING_MAX_BOOST) {
        boost = AEGIS_AGING_MAX_BOOST;
      }
      base = (uint8_t)(base + boost);
    }
    scheduler->credits[i] = base;
    if (base > 0u) {
      scheduler_runnable_credit_inc(scheduler, scheduler->priorities[i]);
    }
  }
}

static void record_switch_reason(aegis_scheduler_t *scheduler, uint8_t reason) {
  uint32_t idx;
  if (scheduler == 0 || reason > AEGIS_SWITCH_MANUAL_YIELD) {
    return;
  }
  scheduler->reason_switch_counts[reason] += 1;
  idx = scheduler->reason_switch_window_head % AEGIS_SCHEDULER_REASON_HISTOGRAM_WINDOW;
  scheduler->reason_switch_window[idx] = reason;
  scheduler->reason_switch_window_head =
      (scheduler->reason_switch_window_head + 1u) % AEGIS_SCHEDULER_REASON_HISTOGRAM_WINDOW;
  if (scheduler->reason_switch_window_count < AEGIS_SCHEDULER_REASON_HISTOGRAM_WINDOW) {
    scheduler->reason_switch_window_count += 1u;
  }
}

static int scheduler_pick_turbo_index(const aegis_scheduler_t *scheduler, size_t *index_out) {
  size_t i;
  int best_score = -2147483647;
  size_t best_index = 0u;
  int found = 0;
  if (scheduler == 0 || index_out == 0 || scheduler->count == 0u) {
    return 0;
  }
  if (scheduler->turbo_candidate_cache_valid != 0u &&
      scheduler->turbo_candidate_cache_index < scheduler->count &&
      scheduler->turbo_candidate_cache_budget > 0u) {
    size_t cached_idx = scheduler->turbo_candidate_cache_index;
    if (scheduler->credits[cached_idx] > 0u) {
      *index_out = cached_idx;
      ((aegis_scheduler_t *)scheduler)->turbo_candidate_cache_budget -= 1u;
      ((aegis_scheduler_t *)scheduler)->turbo_candidate_cache_hits += 1u;
      return 1;
    }
  }
  ((aegis_scheduler_t *)scheduler)->turbo_candidate_cache_misses += 1u;
  for (i = 0; i < scheduler->count; ++i) {
    uint64_t waited_ticks = scheduler->scheduler_ticks - scheduler->enqueued_tick[i];
    int score;
    if (scheduler->credits[i] == 0u) {
      continue;
    }
    score = (int)(scheduler->priorities[i] * scheduler->turbo_priority_weight);
    score += (int)(waited_ticks * scheduler->turbo_wait_weight);
    score -= (int)(scheduler->dispatch_counts[i] / 4u);
    if (scheduler->process_ids[i] == scheduler->turbo_last_pid) {
      score += 3;
    }
    if (!found || score > best_score ||
        (score == best_score &&
         scheduler->enqueued_tick[i] < scheduler->enqueued_tick[best_index])) {
      found = 1;
      best_score = score;
      best_index = i;
    }
  }
  if (!found) {
    return 0;
  }
  ((aegis_scheduler_t *)scheduler)->turbo_candidate_cache_valid = 1u;
  ((aegis_scheduler_t *)scheduler)->turbo_candidate_cache_index = (uint32_t)best_index;
  ((aegis_scheduler_t *)scheduler)->turbo_candidate_cache_budget =
      scheduler->turbo_candidate_cache_max_reuse;
  *index_out = best_index;
  return 1;
}

static uint64_t scheduler_total_switches(const aegis_scheduler_t *scheduler) {
  if (scheduler == 0) {
    return 0u;
  }
  return scheduler->reason_switch_counts[AEGIS_SWITCH_PROCESS_START] +
         scheduler->reason_switch_counts[AEGIS_SWITCH_QUANTUM_EXPIRED] +
         scheduler->reason_switch_counts[AEGIS_SWITCH_PROCESS_EXIT] +
         scheduler->reason_switch_counts[AEGIS_SWITCH_MANUAL_YIELD];
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
  scheduler->quantum_autotune_enabled = 1u;
  scheduler->quantum_autotune_interval_ticks = 64u;
  scheduler->quantum_autotune_min_ticks = 1u;
  scheduler->quantum_autotune_max_ticks = 6u;
  scheduler->quantum_autotune_last_tick = 0u;
  scheduler->quantum_autotune_last_switch_total = 0u;
  scheduler->quantum_autotune_adjustments = 0u;
  scheduler->dispatch_strategy = AEGIS_SCHED_STRATEGY_ROUND_ROBIN;
  scheduler->turbo_wait_weight = 2u;
  scheduler->turbo_priority_weight = 4u;
  scheduler->turbo_autotune_enabled = 1u;
  scheduler->turbo_autotune_interval_ticks = 32u;
  scheduler->turbo_autotune_last_tick = 0u;
  scheduler->turbo_autotune_adjustments = 0u;
  scheduler->turbo_candidate_cache_valid = 0u;
  scheduler->turbo_candidate_cache_budget = 0u;
  scheduler->turbo_candidate_cache_max_reuse = 1u;
  scheduler->turbo_candidate_cache_index = 0u;
  scheduler->turbo_candidate_cache_hits = 0u;
  scheduler->turbo_candidate_cache_misses = 0u;
  scheduler->turbo_last_pid = 0u;
  scheduler->admission_profile_id = AEGIS_SCHED_ADMISSION_PROFILE_CUSTOM;
  scheduler->runnable_credit_count = 0u;
  scheduler->priority_present_bitmap = 0u;
  scheduler->runnable_priority_bitmap = 0u;
  scheduler->reason_switch_window_head = 0;
  scheduler->reason_switch_window_count = 0;
  for (i = 0; i < AEGIS_SCHEDULER_CAPACITY; ++i) {
    scheduler->process_ids[i] = 0;
    scheduler->priorities[i] = AEGIS_PRIORITY_NORMAL;
    scheduler->credits[i] = 0;
    scheduler->dispatch_counts[i] = 0;
    scheduler->enqueued_tick[i] = 0;
    scheduler->wait_ticks_total[i] = 0;
    scheduler->last_wait_latency[i] = 0;
  }
  for (i = 0; i < 4u; ++i) {
    scheduler->admission_limits[i] = 0u;
    scheduler->priority_counts[i] = 0u;
    scheduler->runnable_priority_counts[i] = 0u;
    scheduler->admission_drops[i] = 0u;
  }
  for (i = 0; i < 5u; ++i) {
    scheduler->reason_switch_counts[i] = 0;
  }
  for (i = 0; i < AEGIS_SCHEDULER_REASON_HISTOGRAM_WINDOW; ++i) {
    scheduler->reason_switch_window[i] = AEGIS_SWITCH_NONE;
  }
  scheduler->turbo_autotune_last_tick = 0u;
  scheduler->turbo_last_pid = 0u;
  scheduler->turbo_candidate_cache_valid = 0u;
  scheduler->turbo_candidate_cache_budget = 0u;
  scheduler->turbo_candidate_cache_hits = 0u;
  scheduler->turbo_candidate_cache_misses = 0u;
  scheduler->quantum_autotune_last_tick = 0u;
  scheduler->quantum_autotune_last_switch_total = 0u;
  scheduler->quantum_autotune_adjustments = 0u;
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
  uint8_t normalized_priority;
  int bucket;
  uint8_t limit = 0u;
  if (scheduler == 0 || process_id == 0) {
    return -1;
  }
  if (scheduler->count >= AEGIS_SCHEDULER_CAPACITY) {
    return -1;
  }
  if (find_index(scheduler, process_id, &existing)) {
    return -1;
  }
  normalized_priority = normalize_priority(priority);
  bucket = priority_bucket_index(normalized_priority);
  if (bucket < 0) {
    return -1;
  }
  limit = scheduler->admission_limits[(size_t)bucket];
  if (limit > 0u &&
      scheduler_priority_member_count(scheduler, normalized_priority) >= limit) {
    scheduler->admission_drops[(size_t)bucket] += 1u;
    return -1;
  }
  scheduler->process_ids[scheduler->count] = process_id;
  scheduler->priorities[scheduler->count] = normalized_priority;
  scheduler->credits[scheduler->count] = scheduler->priorities[scheduler->count];
  scheduler->dispatch_counts[scheduler->count] = 0;
  scheduler->enqueued_tick[scheduler->count] = scheduler->scheduler_ticks;
  scheduler->wait_ticks_total[scheduler->count] = 0;
  scheduler->last_wait_latency[scheduler->count] = 0;
  scheduler->priority_counts[(size_t)bucket] += 1u;
  scheduler_set_priority_present(scheduler, normalized_priority, 1u);
  if (scheduler->credits[scheduler->count] > 0u) {
    scheduler_runnable_credit_inc(scheduler, normalized_priority);
  }
  scheduler->turbo_candidate_cache_valid = 0u;
  scheduler->turbo_candidate_cache_budget = 0u;
  scheduler->count += 1;
  if (scheduler->count > scheduler->high_watermark) {
    scheduler->high_watermark = scheduler->count;
  }
  return 0;
}

int aegis_scheduler_remove(aegis_scheduler_t *scheduler, uint32_t process_id) {
  size_t idx = 0;
  size_t i;
  uint8_t removed_priority;
  int removed_bucket;
  uint8_t removed_credit;
  if (scheduler == 0) {
    return -1;
  }
  if (!find_index(scheduler, process_id, &idx)) {
    return -1;
  }
  removed_priority = scheduler->priorities[idx];
  removed_bucket = priority_bucket_index(removed_priority);
  removed_credit = scheduler->credits[idx];
  if (removed_bucket >= 0 && scheduler->priority_counts[(size_t)removed_bucket] > 0u) {
    scheduler->priority_counts[(size_t)removed_bucket] -= 1u;
    if (scheduler->priority_counts[(size_t)removed_bucket] == 0u) {
      scheduler_set_priority_present(scheduler, removed_priority, 0u);
    }
  }
  if (removed_credit > 0u) {
    scheduler_runnable_credit_dec(scheduler, removed_priority);
  }
  scheduler->turbo_candidate_cache_valid = 0u;
  scheduler->turbo_candidate_cache_budget = 0u;
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
  uint8_t old_priority;
  uint8_t new_priority;
  int old_bucket;
  int new_bucket;
  if (scheduler == 0 || !find_index(scheduler, process_id, &idx)) {
    return -1;
  }
  old_priority = scheduler->priorities[idx];
  new_priority = normalize_priority(priority);
  old_bucket = priority_bucket_index(old_priority);
  new_bucket = priority_bucket_index(new_priority);
  if (old_bucket >= 0 && scheduler->priority_counts[(size_t)old_bucket] > 0u) {
    scheduler->priority_counts[(size_t)old_bucket] -= 1u;
    if (scheduler->priority_counts[(size_t)old_bucket] == 0u) {
      scheduler_set_priority_present(scheduler, old_priority, 0u);
    }
  }
  if (new_bucket >= 0) {
    scheduler->priority_counts[(size_t)new_bucket] += 1u;
    scheduler_set_priority_present(scheduler, new_priority, 1u);
  }
  scheduler->priorities[idx] = new_priority;
  if (scheduler->credits[idx] > 0u) {
    scheduler_runnable_credit_dec(scheduler, old_priority);
  }
  scheduler->credits[idx] = scheduler->priorities[idx];
  if (scheduler->credits[idx] > 0u) {
    scheduler_runnable_credit_inc(scheduler, new_priority);
  }
  scheduler->turbo_candidate_cache_valid = 0u;
  scheduler->turbo_candidate_cache_budget = 0u;
  return 0;
}

int aegis_scheduler_next(aegis_scheduler_t *scheduler, uint32_t *process_id) {
  size_t attempts;
  size_t chosen_idx = 0u;
  if (scheduler == 0 || process_id == 0 || scheduler->count == 0) {
    return -1;
  }
  if (scheduler->runnable_credit_count == 0u) {
    refill_credits(scheduler);
  }
  if (scheduler->dispatch_strategy == AEGIS_SCHED_STRATEGY_TURBO &&
      scheduler_pick_turbo_index(scheduler, &chosen_idx)) {
    scheduler->credits[chosen_idx] -= 1;
    if (scheduler->credits[chosen_idx] == 0u) {
      scheduler_runnable_credit_dec(scheduler, scheduler->priorities[chosen_idx]);
    }
    scheduler->last_wait_latency[chosen_idx] =
        scheduler->scheduler_ticks - scheduler->enqueued_tick[chosen_idx];
    scheduler->wait_ticks_total[chosen_idx] += scheduler->last_wait_latency[chosen_idx];
    scheduler->dispatch_counts[chosen_idx] += 1;
    scheduler->total_dispatches += 1;
    *process_id = scheduler->process_ids[chosen_idx];
    scheduler->head = (chosen_idx + 1u) % scheduler->count;
    scheduler->enqueued_tick[chosen_idx] = scheduler->scheduler_ticks;
    scheduler->turbo_last_pid = *process_id;
    return 0;
  }
  for (attempts = 0; attempts < scheduler->count; ++attempts) {
    size_t idx = (scheduler->head + attempts) % scheduler->count;
    if (scheduler->credits[idx] == 0) {
      continue;
    }
    scheduler->credits[idx] -= 1;
    if (scheduler->credits[idx] == 0u) {
      scheduler_runnable_credit_dec(scheduler, scheduler->priorities[idx]);
    }
    scheduler->last_wait_latency[idx] = scheduler->scheduler_ticks - scheduler->enqueued_tick[idx];
    scheduler->wait_ticks_total[idx] += scheduler->last_wait_latency[idx];
    scheduler->dispatch_counts[idx] += 1;
    scheduler->total_dispatches += 1;
    *process_id = scheduler->process_ids[idx];
    scheduler->head = (idx + 1) % scheduler->count;
    scheduler->enqueued_tick[idx] = scheduler->scheduler_ticks;
    scheduler->turbo_last_pid = *process_id;
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
  size_t b;
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
    scheduler->credits[i] = normalize_priority(scheduler->priorities[i]);
  }
  scheduler->runnable_credit_count = 0u;
  scheduler->runnable_priority_bitmap = 0u;
  for (b = 0u; b < 4u; ++b) {
    scheduler->runnable_priority_counts[b] = 0u;
  }
  for (i = 0; i < scheduler->count; ++i) {
    if (scheduler->credits[i] > 0u) {
      scheduler_runnable_credit_inc(scheduler, scheduler->priorities[i]);
    }
  }
  for (i = 0; i < 5u; ++i) {
    scheduler->reason_switch_counts[i] = 0;
  }
  for (i = 0; i < 4u; ++i) {
    scheduler->admission_drops[i] = 0u;
  }
  scheduler->reason_switch_window_head = 0;
  scheduler->reason_switch_window_count = 0;
  for (i = 0; i < AEGIS_SCHEDULER_REASON_HISTOGRAM_WINDOW; ++i) {
    scheduler->reason_switch_window[i] = AEGIS_SWITCH_NONE;
  }
  scheduler->turbo_autotune_last_tick = scheduler->scheduler_ticks;
  scheduler->turbo_candidate_cache_valid = 0u;
  scheduler->turbo_candidate_cache_budget = 0u;
  scheduler->turbo_candidate_cache_hits = 0u;
  scheduler->turbo_candidate_cache_misses = 0u;
  scheduler->quantum_autotune_last_tick = scheduler->scheduler_ticks;
  scheduler->quantum_autotune_last_switch_total = 0u;
  scheduler->quantum_autotune_adjustments = 0u;
}

void aegis_scheduler_set_quantum(aegis_scheduler_t *scheduler, uint32_t quantum_ticks) {
  if (scheduler == 0 || quantum_ticks == 0) {
    return;
  }
  if (scheduler->quantum_autotune_min_ticks > 0u &&
      quantum_ticks < scheduler->quantum_autotune_min_ticks) {
    quantum_ticks = scheduler->quantum_autotune_min_ticks;
  }
  if (scheduler->quantum_autotune_max_ticks > 0u &&
      quantum_ticks > scheduler->quantum_autotune_max_ticks) {
    quantum_ticks = scheduler->quantum_autotune_max_ticks;
  }
  scheduler->quantum_ticks = quantum_ticks;
  if (scheduler->quantum_remaining > quantum_ticks) {
    scheduler->quantum_remaining = quantum_ticks;
  }
}

void aegis_scheduler_enable_quantum_autotune(aegis_scheduler_t *scheduler,
                                             uint8_t enabled,
                                             uint32_t interval_ticks,
                                             uint32_t min_ticks,
                                             uint32_t max_ticks) {
  if (scheduler == 0) {
    return;
  }
  scheduler->quantum_autotune_enabled = enabled != 0u ? 1u : 0u;
  if (interval_ticks > 0u) {
    scheduler->quantum_autotune_interval_ticks = interval_ticks;
  }
  if (min_ticks == 0u) {
    min_ticks = 1u;
  }
  if (max_ticks == 0u || max_ticks < min_ticks) {
    max_ticks = min_ticks;
  }
  scheduler->quantum_autotune_min_ticks = min_ticks;
  scheduler->quantum_autotune_max_ticks = max_ticks;
  aegis_scheduler_set_quantum(scheduler, scheduler->quantum_ticks);
}

void aegis_scheduler_enable_turbo(aegis_scheduler_t *scheduler, uint8_t enabled) {
  if (scheduler == 0) {
    return;
  }
  scheduler->dispatch_strategy =
      enabled != 0u ? AEGIS_SCHED_STRATEGY_TURBO : AEGIS_SCHED_STRATEGY_ROUND_ROBIN;
  scheduler->turbo_candidate_cache_valid = 0u;
  scheduler->turbo_candidate_cache_budget = 0u;
}

void aegis_scheduler_set_turbo_weights(aegis_scheduler_t *scheduler,
                                       uint8_t wait_weight,
                                       uint8_t priority_weight) {
  if (scheduler == 0 || wait_weight == 0u || priority_weight == 0u) {
    return;
  }
  scheduler->turbo_wait_weight = wait_weight;
  scheduler->turbo_priority_weight = priority_weight;
  scheduler->turbo_candidate_cache_valid = 0u;
  scheduler->turbo_candidate_cache_budget = 0u;
}

void aegis_scheduler_enable_turbo_autotune(aegis_scheduler_t *scheduler,
                                           uint8_t enabled,
                                           uint32_t interval_ticks) {
  if (scheduler == 0) {
    return;
  }
  scheduler->turbo_autotune_enabled = enabled != 0u ? 1u : 0u;
  if (interval_ticks > 0u) {
    scheduler->turbo_autotune_interval_ticks = interval_ticks;
  }
  scheduler->turbo_candidate_cache_valid = 0u;
  scheduler->turbo_candidate_cache_budget = 0u;
}

static void aegis_scheduler_turbo_autotune_step(aegis_scheduler_t *scheduler) {
  size_t i;
  uint64_t high_wait_sum = 0u;
  uint64_t low_wait_sum = 0u;
  uint32_t high_count = 0u;
  uint32_t low_count = 0u;
  if (scheduler == 0 || scheduler->dispatch_strategy != AEGIS_SCHED_STRATEGY_TURBO ||
      scheduler->turbo_autotune_enabled == 0u || scheduler->count == 0u) {
    return;
  }
  if (scheduler->turbo_autotune_interval_ticks == 0u) {
    scheduler->turbo_autotune_interval_ticks = 32u;
  }
  if (scheduler->scheduler_ticks - scheduler->turbo_autotune_last_tick <
      scheduler->turbo_autotune_interval_ticks) {
    return;
  }
  scheduler->turbo_autotune_last_tick = scheduler->scheduler_ticks;
  for (i = 0; i < scheduler->count; ++i) {
    if (scheduler->priorities[i] >= AEGIS_PRIORITY_HIGH) {
      high_wait_sum += scheduler->last_wait_latency[i];
      high_count += 1u;
    } else {
      low_wait_sum += scheduler->last_wait_latency[i];
      low_count += 1u;
    }
  }
  if (high_count > 0u && low_count > 0u) {
    uint64_t high_wait_mean = high_wait_sum / high_count;
    uint64_t low_wait_mean = low_wait_sum / low_count;
    if (high_wait_mean > low_wait_mean + 2u && scheduler->turbo_priority_weight < 8u) {
      scheduler->turbo_priority_weight += 1u;
      scheduler->turbo_autotune_adjustments += 1u;
    } else if (low_wait_mean > high_wait_mean + 4u && scheduler->turbo_wait_weight < 6u) {
      scheduler->turbo_wait_weight += 1u;
      scheduler->turbo_autotune_adjustments += 1u;
    } else if (scheduler->turbo_priority_weight > 3u && scheduler->turbo_wait_weight > 1u) {
      scheduler->turbo_priority_weight -= 1u;
      scheduler->turbo_wait_weight -= 1u;
      scheduler->turbo_autotune_adjustments += 1u;
    }
  }
}

static void aegis_scheduler_quantum_autotune_step(aegis_scheduler_t *scheduler) {
  uint64_t switch_total;
  uint64_t switch_delta;
  uint64_t elapsed_ticks;
  uint64_t switch_pressure_bps;
  aegis_scheduler_wait_report_t report;
  if (scheduler == 0 || scheduler->quantum_autotune_enabled == 0u || scheduler->count == 0u) {
    return;
  }
  if (scheduler->quantum_autotune_interval_ticks == 0u) {
    scheduler->quantum_autotune_interval_ticks = 64u;
  }
  if (scheduler->scheduler_ticks - scheduler->quantum_autotune_last_tick <
      scheduler->quantum_autotune_interval_ticks) {
    return;
  }
  elapsed_ticks = scheduler->scheduler_ticks - scheduler->quantum_autotune_last_tick;
  if (elapsed_ticks == 0u || aegis_scheduler_wait_report(scheduler, &report) != 0) {
    return;
  }
  switch_total = scheduler_total_switches(scheduler);
  switch_delta = switch_total - scheduler->quantum_autotune_last_switch_total;
  switch_pressure_bps = (switch_delta * 10000u) / elapsed_ticks;
  if (report.p95_wait_ticks > 8u && scheduler->quantum_ticks > scheduler->quantum_autotune_min_ticks) {
    scheduler->quantum_ticks -= 1u;
    if (scheduler->quantum_remaining > scheduler->quantum_ticks) {
      scheduler->quantum_remaining = scheduler->quantum_ticks;
    }
    scheduler->quantum_autotune_adjustments += 1u;
  } else if (report.p95_wait_ticks <= 2u && switch_pressure_bps > 7000u &&
             scheduler->quantum_ticks < scheduler->quantum_autotune_max_ticks) {
    scheduler->quantum_ticks += 1u;
    scheduler->quantum_autotune_adjustments += 1u;
  }
  scheduler->quantum_autotune_last_tick = scheduler->scheduler_ticks;
  scheduler->quantum_autotune_last_switch_total = switch_total;
}

int aegis_scheduler_turbo_state_json(const aegis_scheduler_t *scheduler, char *out, size_t out_size) {
  int written;
  if (scheduler == 0 || out == 0 || out_size == 0u) {
    return -1;
  }
  written = snprintf(out,
                     out_size,
                     "{\"schema_version\":1,\"dispatch_strategy\":%u,\"turbo_wait_weight\":%u,"
                     "\"turbo_priority_weight\":%u,\"turbo_autotune_enabled\":%u,"
                     "\"turbo_autotune_interval_ticks\":%u,\"turbo_autotune_adjustments\":%llu,"
                     "\"turbo_last_pid\":%u,\"turbo_candidate_cache_hits\":%llu,"
                     "\"turbo_candidate_cache_misses\":%llu,\"turbo_candidate_cache_reuse_budget\":%u}",
                     (unsigned int)scheduler->dispatch_strategy,
                     (unsigned int)scheduler->turbo_wait_weight,
                     (unsigned int)scheduler->turbo_priority_weight,
                     (unsigned int)scheduler->turbo_autotune_enabled,
                     (unsigned int)scheduler->turbo_autotune_interval_ticks,
                     (unsigned long long)scheduler->turbo_autotune_adjustments,
                     scheduler->turbo_last_pid,
                     (unsigned long long)scheduler->turbo_candidate_cache_hits,
                     (unsigned long long)scheduler->turbo_candidate_cache_misses,
                     (unsigned int)scheduler->turbo_candidate_cache_budget);
  if (written < 0 || (size_t)written >= out_size) {
    return -1;
  }
  return written;
}

int aegis_scheduler_quantum_autotune_state_json(const aegis_scheduler_t *scheduler,
                                                char *out,
                                                size_t out_size) {
  int written;
  if (scheduler == 0 || out == 0 || out_size == 0u) {
    return -1;
  }
  written = snprintf(out,
                     out_size,
                     "{\"schema_version\":1,\"quantum_ticks\":%u,\"quantum_autotune_enabled\":%u,"
                     "\"quantum_autotune_interval_ticks\":%u,\"quantum_autotune_min_ticks\":%u,"
                     "\"quantum_autotune_max_ticks\":%u,\"quantum_autotune_adjustments\":%llu}",
                     (unsigned int)scheduler->quantum_ticks,
                     (unsigned int)scheduler->quantum_autotune_enabled,
                     (unsigned int)scheduler->quantum_autotune_interval_ticks,
                     (unsigned int)scheduler->quantum_autotune_min_ticks,
                     (unsigned int)scheduler->quantum_autotune_max_ticks,
                     (unsigned long long)scheduler->quantum_autotune_adjustments);
  if (written < 0 || (size_t)written >= out_size) {
    return -1;
  }
  return written;
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
    record_switch_reason(scheduler, reason);
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
  aegis_scheduler_turbo_autotune_step(scheduler);
  aegis_scheduler_quantum_autotune_step(scheduler);
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
  uint64_t recent_counts[5] = {0, 0, 0, 0, 0};
  uint32_t samples;
  uint32_t i;
  if (scheduler == 0 || snapshot == 0) {
    return -1;
  }
  snapshot->schema_version = AEGIS_SCHEDULER_SNAPSHOT_SCHEMA_VERSION;
  snapshot->queue_depth = scheduler->count;
  snapshot->high_watermark = scheduler->high_watermark;
  snapshot->total_dispatches = scheduler->total_dispatches;
  snapshot->scheduler_ticks = scheduler->scheduler_ticks;
  snapshot->current_pid = scheduler->current_pid;
  snapshot->quantum_ticks = scheduler->quantum_ticks;
  snapshot->quantum_remaining = scheduler->quantum_remaining;
  snapshot->switch_process_start_count = scheduler->reason_switch_counts[AEGIS_SWITCH_PROCESS_START];
  snapshot->switch_quantum_expired_count =
      scheduler->reason_switch_counts[AEGIS_SWITCH_QUANTUM_EXPIRED];
  snapshot->switch_process_exit_count = scheduler->reason_switch_counts[AEGIS_SWITCH_PROCESS_EXIT];
  snapshot->switch_manual_yield_count = scheduler->reason_switch_counts[AEGIS_SWITCH_MANUAL_YIELD];
  snapshot->switch_reason_window_capacity = AEGIS_SCHEDULER_REASON_HISTOGRAM_WINDOW;
  samples = scheduler->reason_switch_window_count;
  snapshot->switch_reason_window_samples = samples;
  for (i = 0; i < samples; ++i) {
    uint32_t idx = (scheduler->reason_switch_window_head + AEGIS_SCHEDULER_REASON_HISTOGRAM_WINDOW -
                    samples + i) %
                   AEGIS_SCHEDULER_REASON_HISTOGRAM_WINDOW;
    uint8_t reason = scheduler->reason_switch_window[idx];
    if (reason <= AEGIS_SWITCH_MANUAL_YIELD) {
      recent_counts[reason] += 1u;
    }
  }
  snapshot->recent_switch_process_start_count = recent_counts[AEGIS_SWITCH_PROCESS_START];
  snapshot->recent_switch_quantum_expired_count = recent_counts[AEGIS_SWITCH_QUANTUM_EXPIRED];
  snapshot->recent_switch_process_exit_count = recent_counts[AEGIS_SWITCH_PROCESS_EXIT];
  snapshot->recent_switch_manual_yield_count = recent_counts[AEGIS_SWITCH_MANUAL_YIELD];
  return 0;
}

int aegis_scheduler_metrics_snapshot_json(const aegis_scheduler_metrics_snapshot_t *snapshot,
                                          char *out, size_t out_size) {
  int written;
  if (snapshot == 0 || out == 0 || out_size == 0u) {
    return -1;
  }
  written = snprintf(out, out_size,
                     "{\"schema_version\":%u,\"queue_depth\":%llu,\"high_watermark\":%llu,"
                     "\"total_dispatches\":%llu,"
                     "\"scheduler_ticks\":%llu,\"current_pid\":%u,\"quantum_ticks\":%u,"
                     "\"quantum_remaining\":%u,\"switch_process_start_count\":%llu,"
                     "\"switch_quantum_expired_count\":%llu,\"switch_process_exit_count\":%llu,"
                     "\"switch_manual_yield_count\":%llu,\"switch_reason_window_capacity\":%u,"
                     "\"switch_reason_window_samples\":%u,\"recent_switch_process_start_count\":%llu,"
                     "\"recent_switch_quantum_expired_count\":%llu,"
                     "\"recent_switch_process_exit_count\":%llu,"
                     "\"recent_switch_manual_yield_count\":%llu}",
                     snapshot->schema_version, (unsigned long long)snapshot->queue_depth,
                     (unsigned long long)snapshot->high_watermark,
                     (unsigned long long)snapshot->total_dispatches,
                     (unsigned long long)snapshot->scheduler_ticks, snapshot->current_pid,
                     snapshot->quantum_ticks, snapshot->quantum_remaining,
                     (unsigned long long)snapshot->switch_process_start_count,
                     (unsigned long long)snapshot->switch_quantum_expired_count,
                     (unsigned long long)snapshot->switch_process_exit_count,
                     (unsigned long long)snapshot->switch_manual_yield_count,
                     snapshot->switch_reason_window_capacity,
                     snapshot->switch_reason_window_samples,
                     (unsigned long long)snapshot->recent_switch_process_start_count,
                     (unsigned long long)snapshot->recent_switch_quantum_expired_count,
                     (unsigned long long)snapshot->recent_switch_process_exit_count,
                     (unsigned long long)snapshot->recent_switch_manual_yield_count);
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

int aegis_scheduler_switch_reason_histogram_window(const aegis_scheduler_t *scheduler,
                                                   uint32_t requested_window,
                                                   uint32_t *applied_window,
                                                   uint64_t *process_start_count,
                                                   uint64_t *quantum_expired_count,
                                                   uint64_t *process_exit_count,
                                                   uint64_t *manual_yield_count) {
  uint32_t samples;
  uint32_t i;
  uint64_t counts[5] = {0, 0, 0, 0, 0};
  if (scheduler == 0 || applied_window == 0 || process_start_count == 0 ||
      quantum_expired_count == 0 || process_exit_count == 0 || manual_yield_count == 0) {
    return -1;
  }
  if (requested_window == 0u) {
    return -1;
  }
  samples = scheduler->reason_switch_window_count;
  if (requested_window < samples) {
    samples = requested_window;
  }
  *applied_window = samples;
  for (i = 0; i < samples; ++i) {
    uint32_t idx = (scheduler->reason_switch_window_head + AEGIS_SCHEDULER_REASON_HISTOGRAM_WINDOW -
                    samples + i) %
                   AEGIS_SCHEDULER_REASON_HISTOGRAM_WINDOW;
    uint8_t reason = scheduler->reason_switch_window[idx];
    if (reason <= AEGIS_SWITCH_MANUAL_YIELD) {
      counts[reason] += 1u;
    }
  }
  *process_start_count = counts[AEGIS_SWITCH_PROCESS_START];
  *quantum_expired_count = counts[AEGIS_SWITCH_QUANTUM_EXPIRED];
  *process_exit_count = counts[AEGIS_SWITCH_PROCESS_EXIT];
  *manual_yield_count = counts[AEGIS_SWITCH_MANUAL_YIELD];
  return 0;
}

int aegis_scheduler_switch_reason_histogram_window_json(const aegis_scheduler_t *scheduler,
                                                        uint32_t requested_window,
                                                        char *out,
                                                        size_t out_size) {
  uint32_t applied_window = 0;
  uint64_t process_start_count = 0;
  uint64_t quantum_expired_count = 0;
  uint64_t process_exit_count = 0;
  uint64_t manual_yield_count = 0;
  int written;
  if (out == 0 || out_size == 0u) {
    return -1;
  }
  if (aegis_scheduler_switch_reason_histogram_window(scheduler,
                                                     requested_window,
                                                     &applied_window,
                                                     &process_start_count,
                                                     &quantum_expired_count,
                                                     &process_exit_count,
                                                     &manual_yield_count) != 0) {
    return -1;
  }
  written = snprintf(out,
                     out_size,
                     "{\"schema_version\":1,\"requested_window\":%u,\"applied_window\":%u,"
                     "\"process_start_count\":%llu,\"quantum_expired_count\":%llu,"
                     "\"process_exit_count\":%llu,\"manual_yield_count\":%llu}",
                     requested_window,
                     applied_window,
                     (unsigned long long)process_start_count,
                     (unsigned long long)quantum_expired_count,
                     (unsigned long long)process_exit_count,
                     (unsigned long long)manual_yield_count);
  if (written < 0 || (size_t)written >= out_size) {
    return -1;
  }
  return written;
}

int aegis_scheduler_fairness_snapshot_json(const aegis_scheduler_t *scheduler,
                                           char *out,
                                           size_t out_size) {
  size_t offset = 0;
  size_t i;
  int written = 0;
  if (scheduler == 0 || out == 0 || out_size == 0u) {
    return -1;
  }
  written = snprintf(out,
                     out_size,
                     "{\"schema_version\":1,\"queue_depth\":%llu,\"total_dispatches\":%llu,\"processes\":[",
                     (unsigned long long)scheduler->count,
                     (unsigned long long)scheduler->total_dispatches);
  if (written < 0 || (size_t)written >= out_size) {
    return -1;
  }
  offset = (size_t)written;
  for (i = 0; i < scheduler->count; ++i) {
    uint64_t share_bps = 0u;
    if (scheduler->total_dispatches > 0u) {
      share_bps = (scheduler->dispatch_counts[i] * 10000ull) / scheduler->total_dispatches;
    }
    written = snprintf(out + offset,
                       out_size - offset,
                       "%s{\"process_id\":%u,\"dispatch_count\":%u,\"dispatch_share_bps\":%llu,"
                       "\"wait_ticks_total\":%llu,\"last_wait_latency\":%llu}",
                       i == 0u ? "" : ",",
                       scheduler->process_ids[i],
                       scheduler->dispatch_counts[i],
                       (unsigned long long)share_bps,
                       (unsigned long long)scheduler->wait_ticks_total[i],
                       (unsigned long long)scheduler->last_wait_latency[i]);
    if (written < 0 || (size_t)written >= (out_size - offset)) {
      return -1;
    }
    offset += (size_t)written;
  }
  written = snprintf(out + offset, out_size - offset, "]}");
  if (written < 0 || (size_t)written >= (out_size - offset)) {
    return -1;
  }
  offset += (size_t)written;
  return (int)offset;
}

int aegis_scheduler_set_admission_limit(aegis_scheduler_t *scheduler,
                                        uint8_t priority,
                                        uint8_t max_processes) {
  int bucket;
  if (scheduler == 0) {
    return -1;
  }
  priority = normalize_priority(priority);
  bucket = priority_bucket_index(priority);
  if (bucket < 0) {
    return -1;
  }
  scheduler->admission_limits[(size_t)bucket] = max_processes;
  scheduler->admission_profile_id = AEGIS_SCHED_ADMISSION_PROFILE_CUSTOM;
  return 0;
}

int aegis_scheduler_get_admission_limit(const aegis_scheduler_t *scheduler,
                                        uint8_t priority,
                                        uint8_t *max_processes) {
  int bucket;
  if (scheduler == 0 || max_processes == 0) {
    return -1;
  }
  priority = normalize_priority(priority);
  bucket = priority_bucket_index(priority);
  if (bucket < 0) {
    return -1;
  }
  *max_processes = scheduler->admission_limits[(size_t)bucket];
  return 0;
}

int aegis_scheduler_admission_drop_count(const aegis_scheduler_t *scheduler,
                                         uint8_t priority,
                                         uint64_t *count) {
  int bucket;
  if (scheduler == 0 || count == 0) {
    return -1;
  }
  priority = normalize_priority(priority);
  bucket = priority_bucket_index(priority);
  if (bucket < 0) {
    return -1;
  }
  *count = scheduler->admission_drops[(size_t)bucket];
  return 0;
}

int aegis_scheduler_admission_snapshot_json(const aegis_scheduler_t *scheduler,
                                            char *out,
                                            size_t out_size) {
  uint64_t high_drops;
  uint64_t normal_drops;
  uint64_t low_drops;
  int written;
  if (scheduler == 0 || out == 0 || out_size == 0u) {
    return -1;
  }
  high_drops = scheduler->admission_drops[AEGIS_PRIORITY_HIGH];
  normal_drops = scheduler->admission_drops[AEGIS_PRIORITY_NORMAL];
  low_drops = scheduler->admission_drops[AEGIS_PRIORITY_LOW];
  written = snprintf(out,
                     out_size,
                     "{\"schema_version\":1,\"profile_id\":%u,\"queue_depth\":%llu,"
                     "\"priority_present_bitmap\":%u,\"runnable_priority_bitmap\":%u,"
                     "\"limits\":{\"high\":%u,\"normal\":%u,\"low\":%u},"
                     "\"counts\":{\"high\":%u,\"normal\":%u,\"low\":%u},"
                     "\"drops\":{\"high\":%llu,\"normal\":%llu,\"low\":%llu}}",
                     (unsigned int)scheduler->admission_profile_id,
                     (unsigned long long)scheduler->count,
                     (unsigned int)scheduler->priority_present_bitmap,
                     (unsigned int)scheduler->runnable_priority_bitmap,
                     (unsigned int)scheduler->admission_limits[AEGIS_PRIORITY_HIGH],
                     (unsigned int)scheduler->admission_limits[AEGIS_PRIORITY_NORMAL],
                     (unsigned int)scheduler->admission_limits[AEGIS_PRIORITY_LOW],
                     (unsigned int)scheduler_priority_member_count(scheduler, AEGIS_PRIORITY_HIGH),
                     (unsigned int)scheduler_priority_member_count(scheduler, AEGIS_PRIORITY_NORMAL),
                     (unsigned int)scheduler_priority_member_count(scheduler, AEGIS_PRIORITY_LOW),
                     (unsigned long long)high_drops,
                     (unsigned long long)normal_drops,
                     (unsigned long long)low_drops);
  if (written < 0 || (size_t)written >= out_size) {
    return -1;
  }
  return written;
}

int aegis_scheduler_apply_admission_profile(aegis_scheduler_t *scheduler, uint8_t profile_id) {
  if (scheduler == 0) {
    return -1;
  }
  if (profile_id == AEGIS_SCHED_ADMISSION_PROFILE_MINIMAL) {
    scheduler->admission_limits[AEGIS_PRIORITY_HIGH] = 4u;
    scheduler->admission_limits[AEGIS_PRIORITY_NORMAL] = 8u;
    scheduler->admission_limits[AEGIS_PRIORITY_LOW] = 4u;
  } else if (profile_id == AEGIS_SCHED_ADMISSION_PROFILE_DESKTOP) {
    scheduler->admission_limits[AEGIS_PRIORITY_HIGH] = 8u;
    scheduler->admission_limits[AEGIS_PRIORITY_NORMAL] = 24u;
    scheduler->admission_limits[AEGIS_PRIORITY_LOW] = 12u;
  } else if (profile_id == AEGIS_SCHED_ADMISSION_PROFILE_SERVER) {
    scheduler->admission_limits[AEGIS_PRIORITY_HIGH] = 12u;
    scheduler->admission_limits[AEGIS_PRIORITY_NORMAL] = 36u;
    scheduler->admission_limits[AEGIS_PRIORITY_LOW] = 16u;
  } else {
    return -1;
  }
  scheduler->admission_profile_id = profile_id;
  return 0;
}

int aegis_scheduler_apply_admission_profile_name(aegis_scheduler_t *scheduler,
                                                 const char *profile_name) {
  if (scheduler == 0 || profile_name == 0 || profile_name[0] == '\0') {
    return -1;
  }
  if (strcmp(profile_name, "minimal") == 0) {
    return aegis_scheduler_apply_admission_profile(scheduler, AEGIS_SCHED_ADMISSION_PROFILE_MINIMAL);
  }
  if (strcmp(profile_name, "desktop") == 0) {
    return aegis_scheduler_apply_admission_profile(scheduler, AEGIS_SCHED_ADMISSION_PROFILE_DESKTOP);
  }
  if (strcmp(profile_name, "server") == 0) {
    return aegis_scheduler_apply_admission_profile(scheduler, AEGIS_SCHED_ADMISSION_PROFILE_SERVER);
  }
  return -1;
}

int aegis_scheduler_current_admission_profile(const aegis_scheduler_t *scheduler,
                                              uint8_t *profile_id_out) {
  if (scheduler == 0 || profile_id_out == 0) {
    return -1;
  }
  *profile_id_out = scheduler->admission_profile_id;
  return 0;
}

static int namespace_find_index(const aegis_namespace_table_t *table,
                                uint32_t namespace_id,
                                size_t *index_out) {
  size_t i;
  if (table == 0 || index_out == 0 || namespace_id == 0u) {
    return 0;
  }
  for (i = 0; i < AEGIS_NAMESPACE_CAPACITY; ++i) {
    if (table->namespaces[i].active != 0u &&
        table->namespaces[i].namespace_id == namespace_id) {
      *index_out = i;
      return 1;
    }
  }
  return 0;
}

static int namespace_process_find_by_global(const aegis_namespace_table_t *table,
                                            uint32_t process_id,
                                            size_t *index_out) {
  size_t i;
  if (table == 0 || index_out == 0 || process_id == 0u) {
    return 0;
  }
  for (i = 0; i < AEGIS_NAMESPACE_PROCESS_CAPACITY; ++i) {
    if (table->processes[i].active != 0u &&
        table->processes[i].process_id == process_id) {
      *index_out = i;
      return 1;
    }
  }
  return 0;
}

void aegis_namespace_table_init(aegis_namespace_table_t *table) {
  size_t i;
  if (table == 0) {
    return;
  }
  table->next_namespace_id = 2u;
  table->namespace_count = 0u;
  table->process_count = 0u;
  for (i = 0; i < AEGIS_NAMESPACE_CAPACITY; ++i) {
    table->namespaces[i].namespace_id = 0u;
    table->namespaces[i].parent_namespace_id = 0u;
    table->namespaces[i].member_count = 0u;
    table->namespaces[i].local_pid_counter = 0u;
    table->namespaces[i].active = 0u;
  }
  for (i = 0; i < AEGIS_NAMESPACE_PROCESS_CAPACITY; ++i) {
    table->processes[i].process_id = 0u;
    table->processes[i].namespace_id = 0u;
    table->processes[i].local_pid = 0u;
    table->processes[i].active = 0u;
  }
  table->namespaces[0].namespace_id = 1u;
  table->namespaces[0].parent_namespace_id = 0u;
  table->namespaces[0].member_count = 0u;
  table->namespaces[0].local_pid_counter = 100u;
  table->namespaces[0].active = 1u;
  table->namespace_count = 1u;
}

int aegis_namespace_create(aegis_namespace_table_t *table,
                           uint32_t parent_namespace_id,
                           uint32_t *namespace_id_out) {
  size_t i;
  size_t parent_index = 0u;
  if (table == 0 || namespace_id_out == 0) {
    return -1;
  }
  if (parent_namespace_id != 0u &&
      !namespace_find_index(table, parent_namespace_id, &parent_index)) {
    return -1;
  }
  for (i = 0; i < AEGIS_NAMESPACE_CAPACITY; ++i) {
    if (table->namespaces[i].active != 0u) {
      continue;
    }
    table->namespaces[i].namespace_id = table->next_namespace_id;
    table->namespaces[i].parent_namespace_id = parent_namespace_id;
    table->namespaces[i].member_count = 0u;
    table->namespaces[i].local_pid_counter = 100u;
    table->namespaces[i].active = 1u;
    *namespace_id_out = table->next_namespace_id;
    table->next_namespace_id += 1u;
    table->namespace_count += 1u;
    return 0;
  }
  (void)parent_index;
  return -1;
}

int aegis_namespace_destroy(aegis_namespace_table_t *table, uint32_t namespace_id) {
  size_t ns_index = 0u;
  size_t i;
  if (table == 0 || namespace_id == 0u || namespace_id == 1u) {
    return -1;
  }
  if (!namespace_find_index(table, namespace_id, &ns_index)) {
    return -1;
  }
  for (i = 0; i < AEGIS_NAMESPACE_PROCESS_CAPACITY; ++i) {
    if (table->processes[i].active != 0u &&
        table->processes[i].namespace_id == namespace_id) {
      return -1;
    }
  }
  for (i = 0; i < AEGIS_NAMESPACE_CAPACITY; ++i) {
    if (table->namespaces[i].active != 0u &&
        table->namespaces[i].parent_namespace_id == namespace_id) {
      return -1;
    }
  }
  table->namespaces[ns_index].active = 0u;
  table->namespaces[ns_index].namespace_id = 0u;
  table->namespaces[ns_index].parent_namespace_id = 0u;
  table->namespaces[ns_index].member_count = 0u;
  table->namespaces[ns_index].local_pid_counter = 0u;
  if (table->namespace_count > 0u) {
    table->namespace_count -= 1u;
  }
  return 0;
}

int aegis_namespace_attach_process(aegis_namespace_table_t *table,
                                   uint32_t process_id,
                                   uint32_t namespace_id,
                                   uint32_t *local_pid_out) {
  size_t ns_index = 0u;
  size_t existing = 0u;
  size_t i;
  uint32_t local_pid;
  if (table == 0 || process_id == 0u || local_pid_out == 0) {
    return -1;
  }
  if (!namespace_find_index(table, namespace_id, &ns_index)) {
    return -1;
  }
  if (namespace_process_find_by_global(table, process_id, &existing)) {
    return -1;
  }
  local_pid = table->namespaces[ns_index].local_pid_counter + 1u;
  table->namespaces[ns_index].local_pid_counter = local_pid;
  for (i = 0; i < AEGIS_NAMESPACE_PROCESS_CAPACITY; ++i) {
    if (table->processes[i].active != 0u) {
      continue;
    }
    table->processes[i].process_id = process_id;
    table->processes[i].namespace_id = namespace_id;
    table->processes[i].local_pid = local_pid;
    table->processes[i].active = 1u;
    table->namespaces[ns_index].member_count += 1u;
    table->process_count += 1u;
    *local_pid_out = local_pid;
    return 0;
  }
  return -1;
}

int aegis_namespace_detach_process(aegis_namespace_table_t *table, uint32_t process_id) {
  size_t proc_index = 0u;
  size_t ns_index = 0u;
  if (table == 0 || process_id == 0u) {
    return -1;
  }
  if (!namespace_process_find_by_global(table, process_id, &proc_index)) {
    return -1;
  }
  if (!namespace_find_index(table, table->processes[proc_index].namespace_id, &ns_index)) {
    return -1;
  }
  table->processes[proc_index].active = 0u;
  table->processes[proc_index].process_id = 0u;
  table->processes[proc_index].namespace_id = 0u;
  table->processes[proc_index].local_pid = 0u;
  if (table->namespaces[ns_index].member_count > 0u) {
    table->namespaces[ns_index].member_count -= 1u;
  }
  if (table->process_count > 0u) {
    table->process_count -= 1u;
  }
  return 0;
}

int aegis_namespace_translate_local_to_global(const aegis_namespace_table_t *table,
                                              uint32_t namespace_id,
                                              uint32_t local_pid,
                                              uint32_t *process_id_out) {
  size_t i;
  if (table == 0 || local_pid == 0u || process_id_out == 0) {
    return -1;
  }
  for (i = 0; i < AEGIS_NAMESPACE_PROCESS_CAPACITY; ++i) {
    if (table->processes[i].active == 0u) {
      continue;
    }
    if (table->processes[i].namespace_id == namespace_id &&
        table->processes[i].local_pid == local_pid) {
      *process_id_out = table->processes[i].process_id;
      return 0;
    }
  }
  return -1;
}

int aegis_namespace_translate_global_to_local(const aegis_namespace_table_t *table,
                                              uint32_t namespace_id,
                                              uint32_t process_id,
                                              uint32_t *local_pid_out) {
  size_t i;
  if (table == 0 || process_id == 0u || local_pid_out == 0) {
    return -1;
  }
  for (i = 0; i < AEGIS_NAMESPACE_PROCESS_CAPACITY; ++i) {
    if (table->processes[i].active == 0u) {
      continue;
    }
    if (table->processes[i].namespace_id == namespace_id &&
        table->processes[i].process_id == process_id) {
      *local_pid_out = table->processes[i].local_pid;
      return 0;
    }
  }
  return -1;
}

int aegis_namespace_can_inspect(const aegis_namespace_table_t *table,
                                uint32_t requester_process_id,
                                uint32_t target_process_id,
                                uint8_t *allowed_out) {
  size_t req_index = 0u;
  size_t tgt_index = 0u;
  if (table == 0 || requester_process_id == 0u || target_process_id == 0u || allowed_out == 0) {
    return -1;
  }
  *allowed_out = 0u;
  if (!namespace_process_find_by_global(table, requester_process_id, &req_index) ||
      !namespace_process_find_by_global(table, target_process_id, &tgt_index)) {
    return 0;
  }
  if (table->processes[req_index].namespace_id == table->processes[tgt_index].namespace_id) {
    *allowed_out = 1u;
  }
  return 0;
}

int aegis_namespace_snapshot_json(const aegis_namespace_table_t *table,
                                  char *out,
                                  size_t out_size) {
  size_t i;
  size_t offset = 0u;
  int written;
  int first_ns = 1;
  int first_proc = 1;
  if (table == 0 || out == 0 || out_size == 0u) {
    return -1;
  }
  written = snprintf(out,
                     out_size,
                     "{\"schema_version\":1,\"namespace_count\":%llu,\"process_count\":%llu,"
                     "\"namespaces\":[",
                     (unsigned long long)table->namespace_count,
                     (unsigned long long)table->process_count);
  if (written < 0 || (size_t)written >= out_size) {
    return -1;
  }
  offset = (size_t)written;
  for (i = 0; i < AEGIS_NAMESPACE_CAPACITY; ++i) {
    const aegis_namespace_entry_t *entry = &table->namespaces[i];
    if (entry->active == 0u) {
      continue;
    }
    written = snprintf(out + offset,
                       out_size - offset,
                       "%s{\"namespace_id\":%u,\"parent_namespace_id\":%u,\"member_count\":%u}",
                       first_ns ? "" : ",",
                       entry->namespace_id,
                       entry->parent_namespace_id,
                       entry->member_count);
    if (written < 0 || (size_t)written >= (out_size - offset)) {
      return -1;
    }
    offset += (size_t)written;
    first_ns = 0;
  }
  written = snprintf(out + offset, out_size - offset, "],\"processes\":[");
  if (written < 0 || (size_t)written >= (out_size - offset)) {
    return -1;
  }
  offset += (size_t)written;
  for (i = 0; i < AEGIS_NAMESPACE_PROCESS_CAPACITY; ++i) {
    const aegis_namespace_process_entry_t *proc = &table->processes[i];
    if (proc->active == 0u) {
      continue;
    }
    written = snprintf(out + offset,
                       out_size - offset,
                       "%s{\"process_id\":%u,\"namespace_id\":%u,\"local_pid\":%u}",
                       first_proc ? "" : ",",
                       proc->process_id,
                       proc->namespace_id,
                       proc->local_pid);
    if (written < 0 || (size_t)written >= (out_size - offset)) {
      return -1;
    }
    offset += (size_t)written;
    first_proc = 0;
  }
  written = snprintf(out + offset, out_size - offset, "]}");
  if (written < 0 || (size_t)written >= (out_size - offset)) {
    return -1;
  }
  offset += (size_t)written;
  return (int)offset;
}

static int syscall_process_find_index(const aegis_syscall_gate_matrix_t *matrix,
                                      uint32_t process_id,
                                      size_t *index_out) {
  size_t i;
  if (matrix == 0 || index_out == 0 || process_id == 0u) {
    return 0;
  }
  for (i = 0; i < AEGIS_SYSCALL_GATE_CAPACITY; ++i) {
    if (matrix->process_caps[i].active != 0u &&
        matrix->process_caps[i].process_id == process_id) {
      *index_out = i;
      return 1;
    }
  }
  return 0;
}

static int syscall_rule_find_index(const aegis_syscall_gate_matrix_t *matrix,
                                   uint16_t syscall_id,
                                   size_t *index_out) {
  size_t i;
  if (matrix == 0 || index_out == 0 || syscall_id == 0u) {
    return 0;
  }
  for (i = 0; i < AEGIS_SYSCALL_RULE_CAPACITY; ++i) {
    if (matrix->rules[i].active != 0u &&
        matrix->rules[i].syscall_id == syscall_id) {
      *index_out = i;
      return 1;
    }
  }
  return 0;
}

void aegis_syscall_gate_matrix_init(aegis_syscall_gate_matrix_t *matrix) {
  size_t i;
  if (matrix == 0) {
    return;
  }
  for (i = 0; i < AEGIS_SYSCALL_GATE_CAPACITY; ++i) {
    matrix->process_caps[i].process_id = 0u;
    matrix->process_caps[i].granted_capabilities = 0u;
    matrix->process_caps[i].active = 0u;
  }
  for (i = 0; i < AEGIS_SYSCALL_RULE_CAPACITY; ++i) {
    matrix->rules[i].syscall_id = 0u;
    matrix->rules[i].syscall_class = 0u;
    matrix->rules[i].required_capability = 0u;
    matrix->rules[i].policy_gate_required = 0u;
    matrix->rules[i].active = 0u;
  }
  matrix->allow_count = 0u;
  matrix->deny_missing_rule_count = 0u;
  matrix->deny_missing_process_count = 0u;
  matrix->deny_missing_capability_count = 0u;
  matrix->deny_policy_gate_count = 0u;
}

int aegis_syscall_gate_set_process_caps(aegis_syscall_gate_matrix_t *matrix,
                                        uint32_t process_id,
                                        uint32_t granted_capabilities) {
  size_t i;
  size_t existing = 0u;
  if (matrix == 0 || process_id == 0u) {
    return -1;
  }
  if (syscall_process_find_index(matrix, process_id, &existing)) {
    matrix->process_caps[existing].granted_capabilities = granted_capabilities;
    return 0;
  }
  for (i = 0; i < AEGIS_SYSCALL_GATE_CAPACITY; ++i) {
    if (matrix->process_caps[i].active != 0u) {
      continue;
    }
    matrix->process_caps[i].process_id = process_id;
    matrix->process_caps[i].granted_capabilities = granted_capabilities;
    matrix->process_caps[i].active = 1u;
    return 0;
  }
  return -1;
}

int aegis_syscall_gate_remove_process(aegis_syscall_gate_matrix_t *matrix, uint32_t process_id) {
  size_t existing = 0u;
  if (matrix == 0 || process_id == 0u) {
    return -1;
  }
  if (!syscall_process_find_index(matrix, process_id, &existing)) {
    return -1;
  }
  matrix->process_caps[existing].active = 0u;
  matrix->process_caps[existing].process_id = 0u;
  matrix->process_caps[existing].granted_capabilities = 0u;
  return 0;
}

int aegis_syscall_gate_set_rule(aegis_syscall_gate_matrix_t *matrix,
                                uint16_t syscall_id,
                                uint8_t syscall_class,
                                uint32_t required_capability,
                                uint8_t policy_gate_required) {
  size_t i;
  size_t existing = 0u;
  if (matrix == 0 || syscall_id == 0u) {
    return -1;
  }
  if (syscall_class < AEGIS_SYSCALL_CLASS_FS || syscall_class > AEGIS_SYSCALL_CLASS_IPC) {
    return -1;
  }
  if (syscall_rule_find_index(matrix, syscall_id, &existing)) {
    matrix->rules[existing].syscall_class = syscall_class;
    matrix->rules[existing].required_capability = required_capability;
    matrix->rules[existing].policy_gate_required = policy_gate_required != 0u ? 1u : 0u;
    return 0;
  }
  for (i = 0; i < AEGIS_SYSCALL_RULE_CAPACITY; ++i) {
    if (matrix->rules[i].active != 0u) {
      continue;
    }
    matrix->rules[i].syscall_id = syscall_id;
    matrix->rules[i].syscall_class = syscall_class;
    matrix->rules[i].required_capability = required_capability;
    matrix->rules[i].policy_gate_required = policy_gate_required != 0u ? 1u : 0u;
    matrix->rules[i].active = 1u;
    return 0;
  }
  return -1;
}

int aegis_syscall_gate_check(aegis_syscall_gate_matrix_t *matrix,
                             uint32_t process_id,
                             uint16_t syscall_id,
                             uint8_t policy_gate_allowed,
                             uint8_t *allowed_out) {
  size_t rule_index = 0u;
  size_t proc_index = 0u;
  uint32_t required_caps;
  if (matrix == 0 || process_id == 0u || syscall_id == 0u || allowed_out == 0) {
    return -1;
  }
  *allowed_out = 0u;
  if (!syscall_rule_find_index(matrix, syscall_id, &rule_index)) {
    matrix->deny_missing_rule_count += 1u;
    return 0;
  }
  if (!syscall_process_find_index(matrix, process_id, &proc_index)) {
    matrix->deny_missing_process_count += 1u;
    return 0;
  }
  if (matrix->rules[rule_index].policy_gate_required != 0u && policy_gate_allowed == 0u) {
    matrix->deny_policy_gate_count += 1u;
    return 0;
  }
  required_caps = matrix->rules[rule_index].required_capability;
  if (required_caps != 0u &&
      (matrix->process_caps[proc_index].granted_capabilities & required_caps) != required_caps) {
    matrix->deny_missing_capability_count += 1u;
    return 0;
  }
  matrix->allow_count += 1u;
  *allowed_out = 1u;
  return 1;
}

int aegis_syscall_gate_snapshot_json(const aegis_syscall_gate_matrix_t *matrix,
                                     char *out,
                                     size_t out_size) {
  size_t offset = 0u;
  size_t i;
  int first_rule = 1;
  int first_proc = 1;
  int written;
  if (matrix == 0 || out == 0 || out_size == 0u) {
    return -1;
  }
  written = snprintf(out,
                     out_size,
                     "{\"schema_version\":1,\"allow_count\":%llu,"
                     "\"deny_missing_rule_count\":%llu,\"deny_missing_process_count\":%llu,"
                     "\"deny_missing_capability_count\":%llu,\"deny_policy_gate_count\":%llu,"
                     "\"rules\":[",
                     (unsigned long long)matrix->allow_count,
                     (unsigned long long)matrix->deny_missing_rule_count,
                     (unsigned long long)matrix->deny_missing_process_count,
                     (unsigned long long)matrix->deny_missing_capability_count,
                     (unsigned long long)matrix->deny_policy_gate_count);
  if (written < 0 || (size_t)written >= out_size) {
    return -1;
  }
  offset = (size_t)written;
  for (i = 0; i < AEGIS_SYSCALL_RULE_CAPACITY; ++i) {
    const aegis_syscall_rule_t *rule = &matrix->rules[i];
    if (rule->active == 0u) {
      continue;
    }
    written = snprintf(out + offset,
                       out_size - offset,
                       "%s{\"syscall_id\":%u,\"syscall_class\":%u,"
                       "\"required_capability\":%u,\"policy_gate_required\":%u}",
                       first_rule ? "" : ",",
                       (unsigned int)rule->syscall_id,
                       (unsigned int)rule->syscall_class,
                       (unsigned int)rule->required_capability,
                       (unsigned int)rule->policy_gate_required);
    if (written < 0 || (size_t)written >= (out_size - offset)) {
      return -1;
    }
    offset += (size_t)written;
    first_rule = 0;
  }
  written = snprintf(out + offset, out_size - offset, "],\"process_caps\":[");
  if (written < 0 || (size_t)written >= (out_size - offset)) {
    return -1;
  }
  offset += (size_t)written;
  for (i = 0; i < AEGIS_SYSCALL_GATE_CAPACITY; ++i) {
    const aegis_syscall_process_caps_t *proc = &matrix->process_caps[i];
    if (proc->active == 0u) {
      continue;
    }
    written = snprintf(out + offset,
                       out_size - offset,
                       "%s{\"process_id\":%u,\"granted_capabilities\":%u}",
                       first_proc ? "" : ",",
                       proc->process_id,
                       proc->granted_capabilities);
    if (written < 0 || (size_t)written >= (out_size - offset)) {
      return -1;
    }
    offset += (size_t)written;
    first_proc = 0;
  }
  written = snprintf(out + offset, out_size - offset, "]}");
  if (written < 0 || (size_t)written >= (out_size - offset)) {
    return -1;
  }
  offset += (size_t)written;
  return (int)offset;
}

static int ipc_channel_find_index(const aegis_ipc_channel_table_t *table,
                                  uint32_t channel_id,
                                  size_t *index_out) {
  size_t i;
  if (table == 0 || index_out == 0 || channel_id == 0u) {
    return 0;
  }
  for (i = 0; i < AEGIS_IPC_CHANNEL_CAPACITY; ++i) {
    if (table->channels[i].active != 0u &&
        table->channels[i].channel_id == channel_id) {
      *index_out = i;
      return 1;
    }
  }
  return 0;
}

void aegis_ipc_channel_table_init(aegis_ipc_channel_table_t *table) {
  size_t i;
  if (table == 0) {
    return;
  }
  for (i = 0; i < AEGIS_IPC_CHANNEL_CAPACITY; ++i) {
    table->channels[i].channel_id = 0u;
    table->channels[i].quota_bytes = 0u;
    table->channels[i].inflight_bytes = 0u;
    table->channels[i].accepted_messages = 0u;
    table->channels[i].dropped_messages = 0u;
    table->channels[i].backpressure_events = 0u;
    table->channels[i].active = 0u;
  }
  table->total_accepted_messages = 0u;
  table->total_dropped_messages = 0u;
  table->total_backpressure_events = 0u;
}

int aegis_ipc_channel_configure(aegis_ipc_channel_table_t *table,
                                uint32_t channel_id,
                                uint32_t quota_bytes) {
  size_t i;
  size_t existing = 0u;
  if (table == 0 || channel_id == 0u || quota_bytes == 0u) {
    return -1;
  }
  if (ipc_channel_find_index(table, channel_id, &existing)) {
    table->channels[existing].quota_bytes = quota_bytes;
    if (table->channels[existing].inflight_bytes > quota_bytes) {
      table->channels[existing].inflight_bytes = quota_bytes;
    }
    return 0;
  }
  for (i = 0; i < AEGIS_IPC_CHANNEL_CAPACITY; ++i) {
    if (table->channels[i].active != 0u) {
      continue;
    }
    table->channels[i].channel_id = channel_id;
    table->channels[i].quota_bytes = quota_bytes;
    table->channels[i].inflight_bytes = 0u;
    table->channels[i].accepted_messages = 0u;
    table->channels[i].dropped_messages = 0u;
    table->channels[i].backpressure_events = 0u;
    table->channels[i].active = 1u;
    return 0;
  }
  return -1;
}

int aegis_ipc_channel_reserve_send(aegis_ipc_channel_table_t *table,
                                   uint32_t channel_id,
                                   uint32_t payload_bytes,
                                   uint8_t *accepted_out) {
  size_t index = 0u;
  uint64_t projected;
  if (table == 0 || channel_id == 0u || payload_bytes == 0u || accepted_out == 0) {
    return -1;
  }
  *accepted_out = 0u;
  if (!ipc_channel_find_index(table, channel_id, &index)) {
    return -1;
  }
  projected = (uint64_t)table->channels[index].inflight_bytes + (uint64_t)payload_bytes;
  if (projected > (uint64_t)table->channels[index].quota_bytes) {
    table->channels[index].dropped_messages += 1u;
    table->channels[index].backpressure_events += 1u;
    table->total_dropped_messages += 1u;
    table->total_backpressure_events += 1u;
    return 0;
  }
  table->channels[index].inflight_bytes = (uint32_t)projected;
  table->channels[index].accepted_messages += 1u;
  table->total_accepted_messages += 1u;
  *accepted_out = 1u;
  return 1;
}

int aegis_ipc_channel_drain(aegis_ipc_channel_table_t *table,
                            uint32_t channel_id,
                            uint32_t drained_bytes) {
  size_t index = 0u;
  if (table == 0 || channel_id == 0u || drained_bytes == 0u) {
    return -1;
  }
  if (!ipc_channel_find_index(table, channel_id, &index)) {
    return -1;
  }
  if (drained_bytes >= table->channels[index].inflight_bytes) {
    table->channels[index].inflight_bytes = 0u;
    return 0;
  }
  table->channels[index].inflight_bytes -= drained_bytes;
  return 0;
}

int aegis_ipc_channel_snapshot_json(const aegis_ipc_channel_table_t *table,
                                    char *out,
                                    size_t out_size) {
  size_t offset = 0u;
  size_t i;
  int first = 1;
  int written;
  if (table == 0 || out == 0 || out_size == 0u) {
    return -1;
  }
  written = snprintf(out,
                     out_size,
                     "{\"schema_version\":1,\"total_accepted_messages\":%llu,"
                     "\"total_dropped_messages\":%llu,\"total_backpressure_events\":%llu,"
                     "\"channels\":[",
                     (unsigned long long)table->total_accepted_messages,
                     (unsigned long long)table->total_dropped_messages,
                     (unsigned long long)table->total_backpressure_events);
  if (written < 0 || (size_t)written >= out_size) {
    return -1;
  }
  offset = (size_t)written;
  for (i = 0; i < AEGIS_IPC_CHANNEL_CAPACITY; ++i) {
    const aegis_ipc_channel_state_t *ch = &table->channels[i];
    if (ch->active == 0u) {
      continue;
    }
    written = snprintf(out + offset,
                       out_size - offset,
                       "%s{\"channel_id\":%u,\"quota_bytes\":%u,\"inflight_bytes\":%u,"
                       "\"accepted_messages\":%llu,\"dropped_messages\":%llu,"
                       "\"backpressure_events\":%llu}",
                       first ? "" : ",",
                       ch->channel_id,
                       ch->quota_bytes,
                       ch->inflight_bytes,
                       (unsigned long long)ch->accepted_messages,
                       (unsigned long long)ch->dropped_messages,
                       (unsigned long long)ch->backpressure_events);
    if (written < 0 || (size_t)written >= (out_size - offset)) {
      return -1;
    }
    offset += (size_t)written;
    first = 0;
  }
  written = snprintf(out + offset, out_size - offset, "]}");
  if (written < 0 || (size_t)written >= (out_size - offset)) {
    return -1;
  }
  offset += (size_t)written;
  return (int)offset;
}

static int memory_zone_find_index(const aegis_memory_zone_table_t *table,
                                  uint32_t zone_id,
                                  size_t *index_out) {
  size_t i;
  if (table == 0 || zone_id == 0u || index_out == 0) {
    return 0;
  }
  for (i = 0; i < AEGIS_MEMORY_ZONE_CAPACITY; ++i) {
    if (table->zones[i].active != 0u && table->zones[i].zone_id == zone_id) {
      *index_out = i;
      return 1;
    }
  }
  return 0;
}

void aegis_memory_zone_table_init(aegis_memory_zone_table_t *table) {
  size_t i;
  if (table == 0) {
    return;
  }
  table->total_budget_bytes = 0u;
  table->total_used_bytes = 0u;
  table->denied_charges = 0u;
  table->reclaim_events = 0u;
  for (i = 0; i < AEGIS_MEMORY_ZONE_CAPACITY; ++i) {
    table->zones[i].zone_id = 0u;
    table->zones[i].zone_kind = 0u;
    table->zones[i].budget_bytes = 0u;
    table->zones[i].used_bytes = 0u;
    table->zones[i].high_watermark_bytes = 0u;
    table->zones[i].reclaim_target_bytes = 0u;
    table->zones[i].reclaim_attempts = 0u;
    table->zones[i].reclaim_successes = 0u;
    table->zones[i].reclaim_hook_enabled = 0u;
    table->zones[i].active = 0u;
  }
}

int aegis_memory_zone_configure(aegis_memory_zone_table_t *table,
                                uint32_t zone_id,
                                uint8_t zone_kind,
                                uint64_t budget_bytes) {
  size_t i;
  size_t idx = 0u;
  uint64_t old_budget = 0u;
  if (table == 0 || zone_id == 0u || budget_bytes == 0u) {
    return -1;
  }
  if (zone_kind < AEGIS_MEMORY_ZONE_KERNEL || zone_kind > AEGIS_MEMORY_ZONE_CACHE) {
    return -1;
  }
  if (memory_zone_find_index(table, zone_id, &idx)) {
    old_budget = table->zones[idx].budget_bytes;
    table->zones[idx].zone_kind = zone_kind;
    table->zones[idx].budget_bytes = budget_bytes;
    if (table->total_budget_bytes >= old_budget) {
      table->total_budget_bytes -= old_budget;
    }
    table->total_budget_bytes += budget_bytes;
    if (table->zones[idx].used_bytes > budget_bytes) {
      table->zones[idx].used_bytes = budget_bytes;
    }
    return 0;
  }
  for (i = 0; i < AEGIS_MEMORY_ZONE_CAPACITY; ++i) {
    if (table->zones[i].active != 0u) {
      continue;
    }
    table->zones[i].zone_id = zone_id;
    table->zones[i].zone_kind = zone_kind;
    table->zones[i].budget_bytes = budget_bytes;
    table->zones[i].used_bytes = 0u;
    table->zones[i].high_watermark_bytes = 0u;
    table->zones[i].reclaim_target_bytes = 0u;
    table->zones[i].reclaim_attempts = 0u;
    table->zones[i].reclaim_successes = 0u;
    table->zones[i].reclaim_hook_enabled = 0u;
    table->zones[i].active = 1u;
    table->total_budget_bytes += budget_bytes;
    return 0;
  }
  return -1;
}

int aegis_memory_zone_set_reclaim_hook(aegis_memory_zone_table_t *table,
                                       uint32_t zone_id,
                                       uint8_t enabled,
                                       uint64_t reclaim_target_bytes) {
  size_t idx = 0u;
  if (table == 0 || zone_id == 0u) {
    return -1;
  }
  if (!memory_zone_find_index(table, zone_id, &idx)) {
    return -1;
  }
  table->zones[idx].reclaim_hook_enabled = enabled != 0u ? 1u : 0u;
  table->zones[idx].reclaim_target_bytes = reclaim_target_bytes;
  return 0;
}

int aegis_memory_zone_charge(aegis_memory_zone_table_t *table,
                             uint32_t zone_id,
                             uint64_t bytes,
                             uint8_t *accepted_out) {
  size_t idx = 0u;
  uint64_t projected;
  if (table == 0 || zone_id == 0u || bytes == 0u || accepted_out == 0) {
    return -1;
  }
  *accepted_out = 0u;
  if (!memory_zone_find_index(table, zone_id, &idx)) {
    return -1;
  }
  projected = table->zones[idx].used_bytes + bytes;
  if (projected <= table->zones[idx].budget_bytes) {
    table->zones[idx].used_bytes = projected;
    table->total_used_bytes += bytes;
    if (table->zones[idx].used_bytes > table->zones[idx].high_watermark_bytes) {
      table->zones[idx].high_watermark_bytes = table->zones[idx].used_bytes;
    }
    *accepted_out = 1u;
    return 1;
  }
  if (table->zones[idx].reclaim_hook_enabled != 0u && table->zones[idx].reclaim_target_bytes > 0u) {
    uint64_t reclaimed = table->zones[idx].reclaim_target_bytes;
    table->zones[idx].reclaim_attempts += 1u;
    table->reclaim_events += 1u;
    if (reclaimed > table->zones[idx].used_bytes) {
      reclaimed = table->zones[idx].used_bytes;
    }
    table->zones[idx].used_bytes -= reclaimed;
    if (table->total_used_bytes >= reclaimed) {
      table->total_used_bytes -= reclaimed;
    } else {
      table->total_used_bytes = 0u;
    }
    projected = table->zones[idx].used_bytes + bytes;
    if (projected <= table->zones[idx].budget_bytes) {
      table->zones[idx].used_bytes = projected;
      table->total_used_bytes += bytes;
      table->zones[idx].reclaim_successes += 1u;
      if (table->zones[idx].used_bytes > table->zones[idx].high_watermark_bytes) {
        table->zones[idx].high_watermark_bytes = table->zones[idx].used_bytes;
      }
      *accepted_out = 1u;
      return 1;
    }
  }
  table->denied_charges += 1u;
  return 0;
}

int aegis_memory_zone_release(aegis_memory_zone_table_t *table,
                              uint32_t zone_id,
                              uint64_t bytes) {
  size_t idx = 0u;
  uint64_t drained;
  if (table == 0 || zone_id == 0u || bytes == 0u) {
    return -1;
  }
  if (!memory_zone_find_index(table, zone_id, &idx)) {
    return -1;
  }
  drained = bytes;
  if (drained > table->zones[idx].used_bytes) {
    drained = table->zones[idx].used_bytes;
  }
  table->zones[idx].used_bytes -= drained;
  if (table->total_used_bytes >= drained) {
    table->total_used_bytes -= drained;
  } else {
    table->total_used_bytes = 0u;
  }
  return 0;
}

int aegis_memory_zone_snapshot_json(const aegis_memory_zone_table_t *table,
                                    char *out,
                                    size_t out_size) {
  size_t offset = 0u;
  size_t i;
  int first = 1;
  int written;
  if (table == 0 || out == 0 || out_size == 0u) {
    return -1;
  }
  written = snprintf(out,
                     out_size,
                     "{\"schema_version\":1,\"total_budget_bytes\":%llu,\"total_used_bytes\":%llu,"
                     "\"denied_charges\":%llu,\"reclaim_events\":%llu,\"zones\":[",
                     (unsigned long long)table->total_budget_bytes,
                     (unsigned long long)table->total_used_bytes,
                     (unsigned long long)table->denied_charges,
                     (unsigned long long)table->reclaim_events);
  if (written < 0 || (size_t)written >= out_size) {
    return -1;
  }
  offset = (size_t)written;
  for (i = 0; i < AEGIS_MEMORY_ZONE_CAPACITY; ++i) {
    const aegis_memory_zone_t *zone = &table->zones[i];
    if (zone->active == 0u) {
      continue;
    }
    written = snprintf(
        out + offset,
        out_size - offset,
        "%s{\"zone_id\":%u,\"zone_kind\":%u,\"budget_bytes\":%llu,\"used_bytes\":%llu,"
        "\"high_watermark_bytes\":%llu,\"reclaim_target_bytes\":%llu,\"reclaim_attempts\":%llu,"
        "\"reclaim_successes\":%llu,\"reclaim_hook_enabled\":%u}",
        first ? "" : ",",
        zone->zone_id,
        (unsigned int)zone->zone_kind,
        (unsigned long long)zone->budget_bytes,
        (unsigned long long)zone->used_bytes,
        (unsigned long long)zone->high_watermark_bytes,
        (unsigned long long)zone->reclaim_target_bytes,
        (unsigned long long)zone->reclaim_attempts,
        (unsigned long long)zone->reclaim_successes,
        (unsigned int)zone->reclaim_hook_enabled);
    if (written < 0 || (size_t)written >= (out_size - offset)) {
      return -1;
    }
    offset += (size_t)written;
    first = 0;
  }
  written = snprintf(out + offset, out_size - offset, "]}");
  if (written < 0 || (size_t)written >= (out_size - offset)) {
    return -1;
  }
  offset += (size_t)written;
  return (int)offset;
}
