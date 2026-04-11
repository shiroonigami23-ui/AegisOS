#include "kernel.h"

#include <stdio.h>
#include <string.h>

static int runtime_index_for_pid(const aegis_process_checkpoint_table_t *table,
                                 uint32_t process_id,
                                 size_t *index_out) {
  size_t i;
  if (table == 0 || index_out == 0 || process_id == 0u) {
    return 0;
  }
  for (i = 0; i < AEGIS_PROCESS_CHECKPOINT_CAPACITY; ++i) {
    if (table->runtime_states[i].active != 0u &&
        table->runtime_states[i].process_id == process_id) {
      *index_out = i;
      return 1;
    }
  }
  return 0;
}

static int checkpoint_index_for_pid(const aegis_process_checkpoint_table_t *table,
                                    uint32_t process_id,
                                    size_t *index_out) {
  size_t i;
  if (table == 0 || index_out == 0 || process_id == 0u) {
    return 0;
  }
  for (i = 0; i < AEGIS_PROCESS_CHECKPOINT_CAPACITY; ++i) {
    if (table->checkpoints[i].valid != 0u &&
        table->checkpoints[i].process_id == process_id) {
      *index_out = i;
      return 1;
    }
  }
  return 0;
}

static int valid_checkpoint_reason(uint8_t reason) {
  return reason >= AEGIS_CHECKPOINT_REASON_MANUAL &&
         reason <= AEGIS_CHECKPOINT_REASON_AUTOMATED_RECOVERY;
}

void aegis_process_checkpoint_table_init(aegis_process_checkpoint_table_t *table) {
  size_t i;
  if (table == 0) {
    return;
  }
  table->next_epoch = 1u;
  table->capture_count = 0u;
  table->restore_count = 0u;
  table->restore_failures = 0u;
  for (i = 0; i < AEGIS_PROCESS_CHECKPOINT_CAPACITY; ++i) {
    memset(&table->runtime_states[i], 0, sizeof(table->runtime_states[i]));
    memset(&table->checkpoints[i], 0, sizeof(table->checkpoints[i]));
  }
}

int aegis_process_checkpoint_register_runtime(aegis_process_checkpoint_table_t *table,
                                              const aegis_process_runtime_state_t *state) {
  size_t idx = 0u;
  size_t i;
  if (table == 0 || state == 0 || state->process_id == 0u) {
    return -1;
  }
  if (runtime_index_for_pid(table, state->process_id, &idx)) {
    table->runtime_states[idx] = *state;
    table->runtime_states[idx].active = 1u;
    return 0;
  }
  for (i = 0; i < AEGIS_PROCESS_CHECKPOINT_CAPACITY; ++i) {
    if (table->runtime_states[i].active != 0u) {
      continue;
    }
    table->runtime_states[i] = *state;
    table->runtime_states[i].active = 1u;
    return 0;
  }
  return -1;
}

int aegis_process_checkpoint_capture(aegis_process_checkpoint_table_t *table,
                                     uint32_t process_id,
                                     uint8_t reason,
                                     uint64_t captured_at_tick,
                                     const char *tag,
                                     uint64_t *checkpoint_epoch_out) {
  size_t runtime_idx = 0u;
  size_t checkpoint_idx = 0u;
  size_t i;
  aegis_process_checkpoint_entry_t *entry = 0;
  if (table == 0 || process_id == 0u || checkpoint_epoch_out == 0 ||
      !valid_checkpoint_reason(reason)) {
    return -1;
  }
  if (!runtime_index_for_pid(table, process_id, &runtime_idx)) {
    return -1;
  }
  if (!checkpoint_index_for_pid(table, process_id, &checkpoint_idx)) {
    checkpoint_idx = AEGIS_PROCESS_CHECKPOINT_CAPACITY;
    for (i = 0; i < AEGIS_PROCESS_CHECKPOINT_CAPACITY; ++i) {
      if (table->checkpoints[i].valid == 0u) {
        checkpoint_idx = i;
        break;
      }
    }
    if (checkpoint_idx == AEGIS_PROCESS_CHECKPOINT_CAPACITY) {
      return -1;
    }
  }
  entry = &table->checkpoints[checkpoint_idx];
  entry->process_id = process_id;
  entry->checkpoint_epoch = table->next_epoch;
  entry->captured_at_tick = captured_at_tick;
  entry->reason = reason;
  entry->last_restore_status = 0u;
  entry->valid = 1u;
  entry->state = table->runtime_states[runtime_idx];
  if (tag != 0 && tag[0] != '\0') {
    snprintf(entry->tag, sizeof(entry->tag), "%s", tag);
  } else {
    entry->tag[0] = '\0';
  }
  *checkpoint_epoch_out = table->next_epoch;
  table->next_epoch += 1u;
  table->capture_count += 1u;
  return 0;
}

int aegis_process_checkpoint_restore(aegis_process_checkpoint_table_t *table,
                                     uint32_t process_id,
                                     uint64_t expected_epoch,
                                     aegis_process_runtime_state_t *restored_state_out) {
  size_t checkpoint_idx = 0u;
  if (table == 0 || process_id == 0u || restored_state_out == 0) {
    return -1;
  }
  if (!checkpoint_index_for_pid(table, process_id, &checkpoint_idx)) {
    table->restore_failures += 1u;
    return -1;
  }
  if (expected_epoch != 0u &&
      table->checkpoints[checkpoint_idx].checkpoint_epoch != expected_epoch) {
    table->checkpoints[checkpoint_idx].last_restore_status = 0u;
    table->restore_failures += 1u;
    return -1;
  }
  *restored_state_out = table->checkpoints[checkpoint_idx].state;
  table->checkpoints[checkpoint_idx].restore_count += 1u;
  table->checkpoints[checkpoint_idx].last_restore_status = 1u;
  table->restore_count += 1u;
  return 0;
}

int aegis_process_checkpoint_query(const aegis_process_checkpoint_table_t *table,
                                   uint32_t process_id,
                                   aegis_process_checkpoint_entry_t *entry_out) {
  size_t checkpoint_idx = 0u;
  if (table == 0 || process_id == 0u || entry_out == 0) {
    return -1;
  }
  if (!checkpoint_index_for_pid(table, process_id, &checkpoint_idx)) {
    return -1;
  }
  *entry_out = table->checkpoints[checkpoint_idx];
  return 0;
}

int aegis_process_checkpoint_snapshot_json(const aegis_process_checkpoint_table_t *table,
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
                     "{\"schema_version\":1,\"capture_count\":%llu,\"restore_count\":%llu,"
                     "\"restore_failures\":%llu,\"entries\":[",
                     (unsigned long long)table->capture_count,
                     (unsigned long long)table->restore_count,
                     (unsigned long long)table->restore_failures);
  if (written < 0 || (size_t)written >= out_size) {
    return -1;
  }
  offset = (size_t)written;
  for (i = 0; i < AEGIS_PROCESS_CHECKPOINT_CAPACITY; ++i) {
    const aegis_process_checkpoint_entry_t *entry = &table->checkpoints[i];
    if (entry->valid == 0u) {
      continue;
    }
    written = snprintf(
        out + offset,
        out_size - offset,
        "%s{\"process_id\":%u,\"checkpoint_epoch\":%llu,\"captured_at_tick\":%llu,"
        "\"reason\":%u,\"restore_count\":%u,\"last_restore_status\":%u,"
        "\"namespace_id\":%u,\"thread_count\":%u,\"vm_bytes\":%llu,"
        "\"capability_mask\":%u,\"policy_revision\":%llu,\"scheduler_tick\":%llu,\"tag\":\"%s\"}",
        first ? "" : ",",
        entry->process_id,
        (unsigned long long)entry->checkpoint_epoch,
        (unsigned long long)entry->captured_at_tick,
        (unsigned int)entry->reason,
        (unsigned int)entry->restore_count,
        (unsigned int)entry->last_restore_status,
        entry->state.namespace_id,
        entry->state.thread_count,
        (unsigned long long)entry->state.vm_bytes,
        entry->state.capability_mask,
        (unsigned long long)entry->state.policy_revision,
        (unsigned long long)entry->state.scheduler_tick,
        entry->tag);
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
