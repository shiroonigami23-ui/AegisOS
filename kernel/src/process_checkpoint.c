#include "kernel.h"

#include <stdio.h>
#include <stdlib.h>
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

static void sanitize_tag_for_journal(const char *in_tag, char *out_tag, size_t out_size) {
  size_t i;
  if (out_tag == 0 || out_size == 0u) {
    return;
  }
  if (in_tag == 0 || in_tag[0] == '\0') {
    snprintf(out_tag, out_size, "%s", "-");
    return;
  }
  for (i = 0; i + 1u < out_size && in_tag[i] != '\0'; ++i) {
    char ch = in_tag[i];
    if (ch == ' ' || ch == '\t' || ch == '|' || ch == '\n' || ch == '\r') {
      out_tag[i] = '_';
    } else {
      out_tag[i] = ch;
    }
  }
  out_tag[i] = '\0';
  if (out_tag[0] == '\0') {
    snprintf(out_tag, out_size, "%s", "-");
  }
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

int aegis_process_checkpoint_journal_save(const aegis_process_checkpoint_table_t *table,
                                          const char *journal_path) {
  FILE *f = 0;
  size_t i;
  if (table == 0 || journal_path == 0 || journal_path[0] == '\0') {
    return -1;
  }
  f = fopen(journal_path, "wb");
  if (f == 0) {
    return -1;
  }
  if (fprintf(f,
              "AEGIS_CHECKPOINT_JOURNAL_V1 %llu %llu %llu %llu\n",
              (unsigned long long)table->next_epoch,
              (unsigned long long)table->capture_count,
              (unsigned long long)table->restore_count,
              (unsigned long long)table->restore_failures) < 0) {
    fclose(f);
    return -1;
  }
  for (i = 0; i < AEGIS_PROCESS_CHECKPOINT_CAPACITY; ++i) {
    const aegis_process_checkpoint_entry_t *entry = &table->checkpoints[i];
    char tag[AEGIS_PROCESS_CHECKPOINT_TAG_MAX];
    if (entry->valid == 0u) {
      continue;
    }
    sanitize_tag_for_journal(entry->tag, tag, sizeof(tag));
    if (fprintf(f,
                "E %u %llu %llu %u %u %u %u %u %llu %u %llu %llu %u %s\n",
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
                (unsigned int)entry->state.active,
                tag) < 0) {
      fclose(f);
      return -1;
    }
  }
  if (fclose(f) != 0) {
    return -1;
  }
  return 0;
}

int aegis_process_checkpoint_journal_replay(aegis_process_checkpoint_table_t *table,
                                            const char *journal_path,
                                            uint8_t apply_runtime_states) {
  FILE *f = 0;
  char line[512];
  uint64_t next_epoch = 1u;
  uint64_t capture_count = 0u;
  uint64_t restore_count = 0u;
  uint64_t restore_failures = 0u;
  unsigned long long next_epoch_raw = 0u;
  unsigned long long capture_count_raw = 0u;
  unsigned long long restore_count_raw = 0u;
  unsigned long long restore_failures_raw = 0u;
  uint64_t max_epoch_seen = 0u;
  size_t checkpoint_cursor = 0u;
  if (table == 0 || journal_path == 0 || journal_path[0] == '\0') {
    return -1;
  }
  f = fopen(journal_path, "rb");
  if (f == 0) {
    return -1;
  }
  if (fgets(line, sizeof(line), f) == 0) {
    fclose(f);
    return -1;
  }
  if (sscanf(line,
             "AEGIS_CHECKPOINT_JOURNAL_V1 %llu %llu %llu %llu",
             &next_epoch_raw,
             &capture_count_raw,
             &restore_count_raw,
             &restore_failures_raw) != 4) {
    fclose(f);
    return -1;
  }
  next_epoch = (uint64_t)next_epoch_raw;
  capture_count = (uint64_t)capture_count_raw;
  restore_count = (uint64_t)restore_count_raw;
  restore_failures = (uint64_t)restore_failures_raw;
  aegis_process_checkpoint_table_init(table);
  table->capture_count = capture_count;
  table->restore_count = restore_count;
  table->restore_failures = restore_failures;
  while (fgets(line, sizeof(line), f) != 0) {
    unsigned int process_id = 0u;
    unsigned long long checkpoint_epoch = 0u;
    unsigned long long captured_at_tick = 0u;
    unsigned int reason = 0u;
    unsigned int restore_count_u32 = 0u;
    unsigned int last_restore_status = 0u;
    unsigned int namespace_id = 0u;
    unsigned int thread_count = 0u;
    unsigned long long vm_bytes = 0u;
    unsigned int capability_mask = 0u;
    unsigned long long policy_revision = 0u;
    unsigned long long scheduler_tick = 0u;
    unsigned int active = 0u;
    char tag[AEGIS_PROCESS_CHECKPOINT_TAG_MAX] = {0};
    aegis_process_checkpoint_entry_t *entry = 0;
    if (line[0] == '\0' || line[0] == '\n' || line[0] == '\r') {
      continue;
    }
    if (line[0] != 'E' || line[1] != ' ') {
      fclose(f);
      return -1;
    }
    if (sscanf(line,
               "E %u %llu %llu %u %u %u %u %u %llu %u %llu %llu %u %47s",
               &process_id,
               &checkpoint_epoch,
               &captured_at_tick,
               &reason,
               &restore_count_u32,
               &last_restore_status,
               &namespace_id,
               &thread_count,
               &vm_bytes,
               &capability_mask,
               &policy_revision,
               &scheduler_tick,
               &active,
               tag) != 14) {
      fclose(f);
      return -1;
    }
    if (!valid_checkpoint_reason((uint8_t)reason) ||
        checkpoint_cursor >= AEGIS_PROCESS_CHECKPOINT_CAPACITY ||
        process_id == 0u) {
      fclose(f);
      return -1;
    }
    entry = &table->checkpoints[checkpoint_cursor];
    memset(entry, 0, sizeof(*entry));
    entry->process_id = (uint32_t)process_id;
    entry->checkpoint_epoch = (uint64_t)checkpoint_epoch;
    entry->captured_at_tick = (uint64_t)captured_at_tick;
    entry->reason = (uint8_t)reason;
    entry->restore_count = (uint8_t)restore_count_u32;
    entry->last_restore_status = (uint8_t)last_restore_status;
    entry->state.process_id = (uint32_t)process_id;
    entry->state.namespace_id = (uint32_t)namespace_id;
    entry->state.thread_count = (uint32_t)thread_count;
    entry->state.vm_bytes = (uint64_t)vm_bytes;
    entry->state.capability_mask = (uint32_t)capability_mask;
    entry->state.policy_revision = (uint64_t)policy_revision;
    entry->state.scheduler_tick = (uint64_t)scheduler_tick;
    entry->state.active = (uint8_t)(active != 0u ? 1u : 0u);
    if (strcmp(tag, "-") == 0) {
      entry->tag[0] = '\0';
    } else {
      snprintf(entry->tag, sizeof(entry->tag), "%s", tag);
    }
    entry->valid = 1u;
    if (apply_runtime_states != 0u) {
      if (aegis_process_checkpoint_register_runtime(table, &entry->state) != 0) {
        fclose(f);
        return -1;
      }
    }
    if (entry->checkpoint_epoch > max_epoch_seen) {
      max_epoch_seen = entry->checkpoint_epoch;
    }
    checkpoint_cursor += 1u;
  }
  fclose(f);
  table->next_epoch = next_epoch;
  if (table->next_epoch <= max_epoch_seen) {
    table->next_epoch = max_epoch_seen + 1u;
  }
  return 0;
}
