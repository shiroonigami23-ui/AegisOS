#include "capability.h"

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

static aegis_capability_audit_event_t g_audit_events[512];
static size_t g_audit_count = 0;
static aegis_actor_registry_entry_t g_actor_registry[256];
#define AEGIS_SECRET_SNAPSHOT_MAX_BYTES 65536u
#define AEGIS_SECRET_SNAPSHOT_MAX_LINES 1024u

static size_t capability_audit_base(void) {
  if (g_audit_count > 512u) {
    return g_audit_count - 512u;
  }
  return 0u;
}

static size_t capability_audit_start_from_cursor(size_t cursor) {
  size_t base = capability_audit_base();
  if (cursor < base) {
    return base;
  }
  if (cursor > g_audit_count) {
    return g_audit_count;
  }
  return cursor;
}

static int append_format(char *out, size_t out_size, size_t *offset, const char *fmt, ...) {
  int written = 0;
  va_list args;
  if (out == 0 || offset == 0 || fmt == 0 || *offset >= out_size) {
    return -1;
  }
  va_start(args, fmt);
  written = vsnprintf(out + *offset, out_size - *offset, fmt, args);
  va_end(args);
  if (written < 0 || (size_t)written >= (out_size - *offset)) {
    return -1;
  }
  *offset += (size_t)written;
  return 0;
}

static int append_json_escaped(char *out, size_t out_size, size_t *offset, const char *src) {
  size_t i = 0;
  if (src == 0) {
    return append_format(out, out_size, offset, "");
  }
  while (src[i] != '\0') {
    if (src[i] == '\\' || src[i] == '"') {
      if (append_format(out, out_size, offset, "\\%c", src[i]) != 0) {
        return -1;
      }
    } else {
      if (append_format(out, out_size, offset, "%c", src[i]) != 0) {
        return -1;
      }
    }
    i += 1;
  }
  return 0;
}

static int actor_label_valid(const char *label) {
  size_t i;
  if (label == 0 || label[0] == '\0') {
    return 0;
  }
  for (i = 0; label[i] != '\0'; ++i) {
    char c = label[i];
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' ||
        c == '-' || c == '.') {
      continue;
    }
    return 0;
  }
  return 1;
}

static int actor_identity_valid(uint8_t actor_source, uint32_t actor_id, const char *actor_label) {
  if (actor_source < AEGIS_ACTOR_SYSTEM || actor_source > AEGIS_ACTOR_AUTOMATION) {
    return 0;
  }
  if (actor_source == AEGIS_ACTOR_SYSTEM) {
    return actor_id == 0u;
  }
  if (actor_id == 0u) {
    return 0;
  }
  return actor_label_valid(actor_label);
}

static int actor_registry_find(uint32_t actor_id, uint8_t actor_source, size_t *index) {
  size_t i;
  if (index == 0) {
    return 0;
  }
  for (i = 0; i < 256u; ++i) {
    if (g_actor_registry[i].active == 0 && g_actor_registry[i].revoked == 0) {
      continue;
    }
    if (g_actor_registry[i].actor_id == actor_id && g_actor_registry[i].actor_source == actor_source) {
      *index = i;
      return 1;
    }
  }
  return 0;
}

static int actor_identity_active_in_registry(uint32_t actor_id, uint8_t actor_source,
                                             const char *actor_label) {
  size_t index = 0;
  if (actor_source == AEGIS_ACTOR_SYSTEM) {
    return actor_id == 0u;
  }
  if (!actor_registry_find(actor_id, actor_source, &index)) {
    return 0;
  }
  if (g_actor_registry[index].active == 0 || g_actor_registry[index].revoked != 0) {
    return 0;
  }
  return strcmp(g_actor_registry[index].actor_label, actor_label) == 0;
}

static void capability_audit_log(uint8_t event_type, uint64_t now_epoch, uint32_t process_id,
                                 uint32_t requested_permissions, uint32_t resulting_permissions,
                                 uint32_t actor_id, uint8_t actor_source,
                                 const char *actor_label, const char *reason) {
  size_t index = g_audit_count % 512;
  g_audit_events[index].timestamp_epoch = now_epoch;
  g_audit_events[index].process_id = process_id;
  g_audit_events[index].requested_permissions = requested_permissions;
  g_audit_events[index].resulting_permissions = resulting_permissions;
  g_audit_events[index].actor_id = actor_id;
  g_audit_events[index].actor_source = actor_source;
  if (actor_label != 0) {
    snprintf(g_audit_events[index].actor_label, sizeof(g_audit_events[index].actor_label), "%s",
             actor_label);
  } else {
    g_audit_events[index].actor_label[0] = '\0';
  }
  if (reason != 0) {
    snprintf(g_audit_events[index].reason, sizeof(g_audit_events[index].reason), "%s", reason);
  } else {
    g_audit_events[index].reason[0] = '\0';
  }
  g_audit_events[index].event_type = event_type;
  g_audit_count += 1;
}

static int capability_find_index(const aegis_capability_store_t *store, uint32_t process_id,
                                 size_t *index) {
  size_t i;
  if (store == 0 || index == 0 || process_id == 0) {
    return 0;
  }
  for (i = 0; i < store->count; ++i) {
    if (store->active[i] != 0 && store->tokens[i].process_id == process_id) {
      *index = i;
      return 1;
    }
  }
  return 0;
}

int aegis_capability_validate(const aegis_capability_token_t *token,
                              uint32_t requested_permissions) {
  if (token == 0) {
    return 0;
  }
  if (token->process_id == 0) {
    return 0;
  }
  return (token->permissions & requested_permissions) == requested_permissions;
}

static int capability_expired(const aegis_capability_token_t *token, uint64_t now_epoch) {
  if (token == 0) {
    return 1;
  }
  if (token->expires_at_epoch == 0) {
    return 0;
  }
  return now_epoch >= token->expires_at_epoch;
}

void aegis_capability_store_init(aegis_capability_store_t *store) {
  size_t i;
  if (store == 0) {
    return;
  }
  store->count = 0;
  for (i = 0; i < 128; ++i) {
    store->active[i] = 0;
    store->tokens[i].process_id = 0;
    store->tokens[i].permissions = AEGIS_CAP_NONE;
    store->tokens[i].issued_at_epoch = 0;
    store->tokens[i].expires_at_epoch = 0;
    store->tokens[i].rotation_counter = 0;
  }
}

int aegis_capability_issue(aegis_capability_store_t *store, uint32_t process_id,
                           uint32_t permissions) {
  return aegis_capability_issue_with_ttl(store, process_id, permissions, 0, 0);
}

int aegis_capability_issue_with_ttl(aegis_capability_store_t *store, uint32_t process_id,
                                    uint32_t permissions, uint64_t now_epoch,
                                    uint64_t ttl_seconds) {
  size_t existing = 0;
  if (store == 0 || process_id == 0) {
    return -1;
  }
  if (capability_find_index(store, process_id, &existing)) {
    store->tokens[existing].permissions = permissions;
    store->tokens[existing].issued_at_epoch = now_epoch;
    store->tokens[existing].expires_at_epoch = ttl_seconds == 0 ? 0 : now_epoch + ttl_seconds;
    capability_audit_log(AEGIS_CAP_AUDIT_ISSUE, now_epoch, process_id, permissions, permissions, 0u,
                         AEGIS_ACTOR_SYSTEM, "system", "issue");
    return 0;
  }
  if (store->count >= 128) {
    return -1;
  }
  store->tokens[store->count].process_id = process_id;
  store->tokens[store->count].permissions = permissions;
  store->tokens[store->count].issued_at_epoch = now_epoch;
  store->tokens[store->count].expires_at_epoch = ttl_seconds == 0 ? 0 : now_epoch + ttl_seconds;
  store->tokens[store->count].rotation_counter = 0;
  store->active[store->count] = 1;
  store->count += 1;
  capability_audit_log(AEGIS_CAP_AUDIT_ISSUE, now_epoch, process_id, permissions, permissions, 0u,
                       AEGIS_ACTOR_SYSTEM, "system", "issue");
  return 0;
}

int aegis_capability_rotate(aegis_capability_store_t *store, uint32_t process_id,
                            uint32_t permissions, uint64_t now_epoch, uint64_t ttl_seconds) {
  return aegis_capability_rotate_with_metadata(store, process_id, permissions, now_epoch, ttl_seconds,
                                               0u, "rotate");
}

int aegis_capability_rotate_with_metadata(aegis_capability_store_t *store, uint32_t process_id,
                                          uint32_t permissions, uint64_t now_epoch,
                                          uint64_t ttl_seconds, uint32_t actor_id,
                                          const char *reason) {
  if (actor_id == 0u) {
    return aegis_capability_rotate_with_identity(store, process_id, permissions, now_epoch, ttl_seconds,
                                                 0u, AEGIS_ACTOR_SYSTEM, "system", reason);
  }
  return aegis_capability_rotate_with_identity(store, process_id, permissions, now_epoch, ttl_seconds,
                                               actor_id, AEGIS_ACTOR_AUTOMATION, "automation", reason);
}

int aegis_capability_rotate_with_identity(aegis_capability_store_t *store, uint32_t process_id,
                                          uint32_t permissions, uint64_t now_epoch,
                                          uint64_t ttl_seconds, uint32_t actor_id,
                                          uint8_t actor_source, const char *actor_label,
                                          const char *reason) {
  size_t index = 0;
  if (store == 0 || process_id == 0) {
    return -1;
  }
  if (!actor_identity_valid(actor_source, actor_id, actor_label)) {
    return -1;
  }
  if (!actor_identity_active_in_registry(actor_id, actor_source, actor_label)) {
    return -1;
  }
  if (!capability_find_index(store, process_id, &index)) {
    return -1;
  }
  store->tokens[index].permissions = permissions;
  store->tokens[index].issued_at_epoch = now_epoch;
  store->tokens[index].expires_at_epoch = ttl_seconds == 0 ? 0 : now_epoch + ttl_seconds;
  store->tokens[index].rotation_counter += 1;
  capability_audit_log(AEGIS_CAP_AUDIT_ROTATE, now_epoch, process_id, permissions, permissions, actor_id,
                       actor_source, actor_label, reason != 0 ? reason : "rotate");
  return 0;
}

int aegis_capability_revoke(aegis_capability_store_t *store, uint32_t process_id) {
  return aegis_capability_revoke_with_identity(store,
                                               process_id,
                                               0u,
                                               0u,
                                               AEGIS_ACTOR_SYSTEM,
                                               "system",
                                               "revoke");
}

int aegis_capability_revoke_with_identity(aegis_capability_store_t *store, uint32_t process_id,
                                          uint64_t now_epoch, uint32_t actor_id,
                                          uint8_t actor_source, const char *actor_label,
                                          const char *reason) {
  size_t index = 0;
  if (store == 0 || process_id == 0) {
    return -1;
  }
  if (!actor_identity_valid(actor_source, actor_id, actor_label)) {
    return -1;
  }
  if (!actor_identity_active_in_registry(actor_id, actor_source, actor_label)) {
    return -1;
  }
  if (!capability_find_index(store, process_id, &index)) {
    return -1;
  }
  store->active[index] = 0;
  store->tokens[index].permissions = AEGIS_CAP_NONE;
  store->tokens[index].issued_at_epoch = 0;
  store->tokens[index].expires_at_epoch = 0;
  store->tokens[index].rotation_counter = 0;
  capability_audit_log(AEGIS_CAP_AUDIT_REVOKE,
                       now_epoch,
                       process_id,
                       0,
                       0,
                       actor_id,
                       actor_source,
                       actor_label,
                       reason != 0 ? reason : "revoke");
  return 0;
}

int aegis_capability_is_allowed(const aegis_capability_store_t *store, uint32_t process_id,
                                uint32_t requested_permissions) {
  return aegis_capability_is_allowed_at(store, process_id, requested_permissions, 0);
}

int aegis_capability_is_allowed_at(const aegis_capability_store_t *store, uint32_t process_id,
                                   uint32_t requested_permissions, uint64_t now_epoch) {
  size_t index = 0;
  if (!capability_find_index(store, process_id, &index)) {
    capability_audit_log(AEGIS_CAP_AUDIT_DENY, now_epoch, process_id, requested_permissions, 0, 0u,
                         AEGIS_ACTOR_SYSTEM, "system", "deny:not_found");
    return 0;
  }
  if (now_epoch != 0 && capability_expired(&store->tokens[index], now_epoch)) {
    capability_audit_log(AEGIS_CAP_AUDIT_DENY, now_epoch, process_id, requested_permissions, 0, 0u,
                         AEGIS_ACTOR_SYSTEM, "system", "deny:expired");
    return 0;
  }
  if (aegis_capability_validate(&store->tokens[index], requested_permissions)) {
    capability_audit_log(AEGIS_CAP_AUDIT_ALLOW, now_epoch, process_id, requested_permissions,
                         store->tokens[index].permissions, 0u, AEGIS_ACTOR_SYSTEM, "system", "allow");
    return 1;
  }
  capability_audit_log(AEGIS_CAP_AUDIT_DENY, now_epoch, process_id, requested_permissions,
                       store->tokens[index].permissions, 0u, AEGIS_ACTOR_SYSTEM, "system",
                       "deny:permission");
  return 0;
}

void aegis_capability_audit_reset(void) {
  g_audit_count = 0;
}

size_t aegis_capability_audit_count(void) {
  return g_audit_count;
}

int aegis_capability_audit_get(size_t index, aegis_capability_audit_event_t *event) {
  size_t base = 0;
  if (event == 0 || index >= g_audit_count) {
    return -1;
  }
  base = capability_audit_base();
  if (index < base) {
    return -1;
  }
  *event = g_audit_events[index % 512];
  return 0;
}

int aegis_capability_audit_export_json(char *out, size_t out_size) {
  return aegis_capability_audit_export_json_page(capability_audit_base(), g_audit_count, out, out_size, 0);
}

int aegis_capability_audit_export_csv(char *out, size_t out_size) {
  return aegis_capability_audit_export_csv_page(capability_audit_base(), g_audit_count, out, out_size, 0);
}

int aegis_capability_audit_export_json_page(size_t cursor, size_t limit,
                                            char *out, size_t out_size,
                                            aegis_capability_audit_page_t *page) {
  size_t offset = 0;
  size_t start = capability_audit_start_from_cursor(cursor);
  size_t end = g_audit_count;
  size_t i = 0;
  aegis_capability_audit_event_t event;
  if (limit < (end - start)) {
    end = start + limit;
  }
  if (out == 0 || out_size == 0u) {
    return -1;
  }
  out[0] = '\0';
  if (page != 0) {
    page->next_cursor = end;
    page->exported_count = end - start;
    page->has_more = end < g_audit_count ? 1u : 0u;
  }
  if (append_format(out, out_size, &offset, "[") != 0) {
    return -1;
  }
  for (i = start; i < end; ++i) {
    if (aegis_capability_audit_get(i, &event) != 0) {
      return -1;
    }
    if (i > start) {
      if (append_format(out, out_size, &offset, ",") != 0) {
        return -1;
      }
    }
    if (append_format(out, out_size, &offset,
                      "{\"timestamp_epoch\":%llu,\"process_id\":%u,\"requested_permissions\":%u,"
                      "\"resulting_permissions\":%u,\"actor_id\":%u,\"actor_source\":%u,"
                      "\"actor_label\":\"",
                      (unsigned long long)event.timestamp_epoch, event.process_id,
                      event.requested_permissions, event.resulting_permissions, event.actor_id,
                      event.actor_source) != 0) {
      return -1;
    }
    if (append_json_escaped(out, out_size, &offset, event.actor_label) != 0) {
      return -1;
    }
    if (append_format(out, out_size, &offset, "\",\"event_type\":%u,\"reason\":\"",
                      event.event_type) != 0) {
      return -1;
    }
    if (append_json_escaped(out, out_size, &offset, event.reason) != 0) {
      return -1;
    }
    if (append_format(out, out_size, &offset, "\"}") != 0) {
      return -1;
    }
  }
  if (append_format(out, out_size, &offset, "]") != 0) {
    return -1;
  }
  return (int)offset;
}

int aegis_capability_audit_export_csv_page(size_t cursor, size_t limit,
                                           char *out, size_t out_size,
                                           aegis_capability_audit_page_t *page) {
  size_t offset = 0;
  size_t start = capability_audit_start_from_cursor(cursor);
  size_t end = g_audit_count;
  size_t i = 0;
  aegis_capability_audit_event_t event;
  char safe_reason[64];
  size_t r = 0;
  if (limit < (end - start)) {
    end = start + limit;
  }
  if (out == 0 || out_size == 0u) {
    return -1;
  }
  out[0] = '\0';
  if (page != 0) {
    page->next_cursor = end;
    page->exported_count = end - start;
    page->has_more = end < g_audit_count ? 1u : 0u;
  }
  if (append_format(out, out_size, &offset,
                    "timestamp_epoch,process_id,requested_permissions,resulting_permissions,"
                    "actor_id,actor_source,actor_label,event_type,reason\n") != 0) {
    return -1;
  }
  for (i = start; i < end; ++i) {
    if (aegis_capability_audit_get(i, &event) != 0) {
      return -1;
    }
    snprintf(safe_reason, sizeof(safe_reason), "%s", event.reason);
    for (r = 0; safe_reason[r] != '\0'; ++r) {
      if (safe_reason[r] == ',') {
        safe_reason[r] = ';';
      }
      if (safe_reason[r] == '\n' || safe_reason[r] == '\r') {
        safe_reason[r] = ' ';
      }
    }
    if (append_format(out, out_size, &offset, "%llu,%u,%u,%u,%u,%u,%s,%u,%s\n",
                      (unsigned long long)event.timestamp_epoch, event.process_id,
                      event.requested_permissions, event.resulting_permissions, event.actor_id,
                      event.actor_source, event.actor_label, event.event_type, safe_reason) != 0) {
      return -1;
    }
  }
  return (int)offset;
}

size_t aegis_capability_audit_cursor_for_timestamp(uint64_t timestamp_epoch) {
  size_t base = capability_audit_base();
  size_t i;
  aegis_capability_audit_event_t event;
  if (g_audit_count == 0u) {
    return 0u;
  }
  for (i = base; i < g_audit_count; ++i) {
    if (aegis_capability_audit_get(i, &event) != 0) {
      continue;
    }
    if (event.timestamp_epoch >= timestamp_epoch) {
      return i;
    }
  }
  return g_audit_count;
}

int aegis_capability_audit_file_sink_name(const char *prefix, uint32_t chunk_id,
                                          char *out, size_t out_size) {
  int written;
  if (prefix == 0 || prefix[0] == '\0' || out == 0 || out_size == 0u) {
    return -1;
  }
  written = snprintf(out, out_size, "%s-%04u.log", prefix, chunk_id);
  if (written < 0 || (size_t)written >= out_size) {
    return -1;
  }
  return 0;
}

int aegis_capability_audit_retention_plan(uint32_t latest_chunk_id,
                                          uint32_t retention_window_chunks,
                                          aegis_capability_audit_retention_plan_t *plan) {
  uint32_t keep_from = 0u;
  if (plan == 0 || retention_window_chunks == 0u) {
    return -1;
  }
  if (retention_window_chunks <= latest_chunk_id + 1u) {
    keep_from = latest_chunk_id - retention_window_chunks + 1u;
  }
  plan->latest_chunk_id = latest_chunk_id;
  plan->retention_window_chunks = retention_window_chunks;
  plan->keep_from_chunk_id = keep_from;
  plan->keep_to_chunk_id = latest_chunk_id;
  plan->prune_chunk_count = keep_from;
  return 0;
}

int aegis_capability_audit_prune_candidate_name(const char *prefix,
                                                uint32_t latest_chunk_id,
                                                uint32_t retention_window_chunks,
                                                uint32_t prune_index,
                                                char *out,
                                                size_t out_size) {
  aegis_capability_audit_retention_plan_t plan;
  uint32_t chunk_id;
  if (aegis_capability_audit_retention_plan(latest_chunk_id, retention_window_chunks, &plan) != 0) {
    return -1;
  }
  if (prune_index >= plan.prune_chunk_count) {
    return -1;
  }
  chunk_id = prune_index;
  return aegis_capability_audit_file_sink_name(prefix, chunk_id, out, out_size);
}

void aegis_actor_registry_reset(void) {
  size_t i;
  for (i = 0; i < 256u; ++i) {
    g_actor_registry[i].actor_id = 0u;
    g_actor_registry[i].actor_source = 0u;
    g_actor_registry[i].actor_label[0] = '\0';
    g_actor_registry[i].active = 0u;
    g_actor_registry[i].revoked = 0u;
    g_actor_registry[i].revoked_at_epoch = 0u;
  }
}

int aegis_actor_registry_register(uint32_t actor_id, uint8_t actor_source, const char *actor_label) {
  size_t index = 0;
  size_t free_index = 256u;
  size_t i;
  if (!actor_identity_valid(actor_source, actor_id, actor_label)) {
    return -1;
  }
  if (actor_source == AEGIS_ACTOR_SYSTEM) {
    return 0;
  }
  if (actor_registry_find(actor_id, actor_source, &index)) {
    g_actor_registry[index].active = 1u;
    g_actor_registry[index].revoked = 0u;
    g_actor_registry[index].revoked_at_epoch = 0u;
    snprintf(g_actor_registry[index].actor_label, sizeof(g_actor_registry[index].actor_label), "%s",
             actor_label);
    return 0;
  }
  for (i = 0; i < 256u; ++i) {
    if (g_actor_registry[i].active == 0u && g_actor_registry[i].revoked == 0u) {
      free_index = i;
      break;
    }
  }
  if (free_index == 256u) {
    return -1;
  }
  g_actor_registry[free_index].actor_id = actor_id;
  g_actor_registry[free_index].actor_source = actor_source;
  snprintf(g_actor_registry[free_index].actor_label, sizeof(g_actor_registry[free_index].actor_label), "%s",
           actor_label);
  g_actor_registry[free_index].active = 1u;
  g_actor_registry[free_index].revoked = 0u;
  g_actor_registry[free_index].revoked_at_epoch = 0u;
  return 0;
}

int aegis_actor_registry_lookup(uint32_t actor_id, uint8_t actor_source,
                                aegis_actor_registry_entry_t *entry) {
  size_t index = 0;
  if (entry == 0) {
    return -1;
  }
  if (actor_source == AEGIS_ACTOR_SYSTEM && actor_id == 0u) {
    entry->actor_id = 0u;
    entry->actor_source = AEGIS_ACTOR_SYSTEM;
    snprintf(entry->actor_label, sizeof(entry->actor_label), "%s", "system");
    entry->active = 1u;
    entry->revoked = 0u;
    entry->revoked_at_epoch = 0u;
    return 0;
  }
  if (!actor_registry_find(actor_id, actor_source, &index)) {
    return -1;
  }
  *entry = g_actor_registry[index];
  return 0;
}

int aegis_actor_registry_revoke(uint32_t actor_id, uint8_t actor_source,
                                uint64_t now_epoch, const char *reason) {
  size_t index = 0;
  (void)reason;
  if (actor_source == AEGIS_ACTOR_SYSTEM) {
    return -1;
  }
  if (!actor_registry_find(actor_id, actor_source, &index)) {
    return -1;
  }
  g_actor_registry[index].active = 0u;
  g_actor_registry[index].revoked = 1u;
  g_actor_registry[index].revoked_at_epoch = now_epoch;
  return 0;
}

int aegis_actor_registry_snapshot(char *out, size_t out_size) {
  size_t i;
  size_t offset = 0;
  if (out == 0 || out_size == 0u) {
    return -1;
  }
  out[0] = '\0';
  if (append_format(out,
                    out_size,
                    &offset,
                    "actor_id,actor_source,actor_label,active,revoked,revoked_at_epoch\n") != 0) {
    return -1;
  }
  for (i = 0; i < 256u; ++i) {
    const aegis_actor_registry_entry_t *entry = &g_actor_registry[i];
    if (entry->active == 0u && entry->revoked == 0u) {
      continue;
    }
    if (append_format(out,
                      out_size,
                      &offset,
                      "%u,%u,%s,%u,%u,%llu\n",
                      entry->actor_id,
                      (unsigned int)entry->actor_source,
                      entry->actor_label,
                      (unsigned int)entry->active,
                      (unsigned int)entry->revoked,
                      (unsigned long long)entry->revoked_at_epoch) != 0) {
      return -1;
    }
  }
  return (int)offset;
}

int aegis_actor_registry_restore(const char *snapshot) {
  const char *cursor;
  const char *line_start;
  size_t restored = 0;
  if (snapshot == 0) {
    return -1;
  }
  aegis_actor_registry_reset();
  cursor = snapshot;
  while (*cursor != '\0' && *cursor != '\n') {
    cursor++;
  }
  if (*cursor == '\n') {
    cursor++;
  }
  while (*cursor != '\0') {
    char line[192];
    size_t len = 0;
    uint32_t actor_id = 0u;
    unsigned int actor_source = 0u;
    char actor_label[32];
    unsigned int active = 0u;
    unsigned int revoked = 0u;
    unsigned long long revoked_at = 0ull;
    size_t i;
    line_start = cursor;
    while (*cursor != '\0' && *cursor != '\n') {
      cursor++;
    }
    len = (size_t)(cursor - line_start);
    if (*cursor == '\n') {
      cursor++;
    }
    if (len == 0u) {
      continue;
    }
    if (len >= sizeof(line)) {
      return -1;
    }
    memcpy(line, line_start, len);
    line[len] = '\0';
    actor_label[0] = '\0';
    if (sscanf(line, "%u,%u,%31[^,],%u,%u,%llu", &actor_id, &actor_source, actor_label, &active, &revoked,
               &revoked_at) != 6) {
      return -1;
    }
    if (actor_source < AEGIS_ACTOR_SYSTEM || actor_source > AEGIS_ACTOR_AUTOMATION) {
      return -1;
    }
    if (active == 0u && revoked == 0u) {
      continue;
    }
    for (i = 0; i < 256u; ++i) {
      if (g_actor_registry[i].active == 0u && g_actor_registry[i].revoked == 0u) {
        g_actor_registry[i].actor_id = actor_id;
        g_actor_registry[i].actor_source = (uint8_t)actor_source;
        snprintf(g_actor_registry[i].actor_label, sizeof(g_actor_registry[i].actor_label), "%s",
                 actor_label);
        g_actor_registry[i].active = active != 0u ? 1u : 0u;
        g_actor_registry[i].revoked = revoked != 0u ? 1u : 0u;
        g_actor_registry[i].revoked_at_epoch = (uint64_t)revoked_at;
        restored += 1u;
        break;
      }
    }
    if (i == 256u) {
      return -1;
    }
  }
  return (int)restored;
}

static int secret_key_valid(const char *key) {
  size_t i;
  if (key == 0 || key[0] == '\0') {
    return 0;
  }
  for (i = 0; key[i] != '\0'; ++i) {
    char c = key[i];
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
          c == '_' || c == '-' || c == '.')) {
      return 0;
    }
    if (i >= 30u) {
      return 0;
    }
  }
  return 1;
}

static int secret_find_index(const aegis_secret_store_t *store, const char *key, size_t *index) {
  size_t i;
  if (store == 0 || key == 0 || index == 0) {
    return 0;
  }
  for (i = 0; i < 128u; ++i) {
    if (store->entries[i].active == 0u) {
      continue;
    }
    if (strcmp(store->entries[i].key, key) == 0) {
      *index = i;
      return 1;
    }
  }
  return 0;
}

static char hex_char(unsigned int v) {
  if (v < 10u) {
    return (char)('0' + (char)v);
  }
  return (char)('a' + (char)(v - 10u));
}

static int hex_value(char c) {
  if (c >= '0' && c <= '9') {
    return (int)(c - '0');
  }
  if (c >= 'a' && c <= 'f') {
    return 10 + (int)(c - 'a');
  }
  if (c >= 'A' && c <= 'F') {
    return 10 + (int)(c - 'A');
  }
  return -1;
}

static int secret_value_to_hex(const uint8_t *value, uint32_t value_size, char *hex_out, size_t hex_out_size) {
  uint32_t i;
  if (value == 0 || hex_out == 0 || hex_out_size < ((size_t)value_size * 2u + 1u)) {
    return -1;
  }
  for (i = 0; i < value_size; ++i) {
    hex_out[(size_t)i * 2u] = hex_char((unsigned int)(value[i] >> 4));
    hex_out[(size_t)i * 2u + 1u] = hex_char((unsigned int)(value[i] & 0x0Fu));
  }
  hex_out[(size_t)value_size * 2u] = '\0';
  return 0;
}

static int secret_hex_to_value(const char *hex, uint8_t *value_out, uint32_t value_out_cap, uint32_t *value_size_out) {
  uint32_t i;
  size_t hex_len;
  if (hex == 0 || value_out == 0 || value_size_out == 0) {
    return -1;
  }
  hex_len = strlen(hex);
  if ((hex_len % 2u) != 0u) {
    return -1;
  }
  if ((hex_len / 2u) > value_out_cap) {
    return -1;
  }
  for (i = 0; i < (uint32_t)(hex_len / 2u); ++i) {
    int hi = hex_value(hex[(size_t)i * 2u]);
    int lo = hex_value(hex[(size_t)i * 2u + 1u]);
    if (hi < 0 || lo < 0) {
      return -1;
    }
    value_out[i] = (uint8_t)((hi << 4) | lo);
  }
  *value_size_out = (uint32_t)(hex_len / 2u);
  return 0;
}

static uint64_t secret_fingerprint64(const char *key, const uint8_t *value, uint32_t value_size) {
  uint64_t hash = 1469598103934665603ull;
  size_t i;
  for (i = 0; key != 0 && key[i] != '\0'; ++i) {
    hash ^= (uint64_t)(unsigned char)key[i];
    hash *= 1099511628211ull;
  }
  for (i = 0; i < (size_t)value_size; ++i) {
    hash ^= (uint64_t)value[i];
    hash *= 1099511628211ull;
  }
  return hash;
}

static int parse_u64_hex(const char *text, uint64_t *value_out) {
  size_t i = 0u;
  uint64_t value = 0u;
  if (text == 0 || value_out == 0 || text[0] == '\0') {
    return -1;
  }
  while (text[i] != '\0') {
    int hv = hex_value(text[i]);
    if (hv < 0) {
      return -1;
    }
    value = (value << 4) | (uint64_t)hv;
    i += 1u;
    if (i > 16u) {
      return -1;
    }
  }
  *value_out = value;
  return 0;
}

void aegis_secret_store_init(aegis_secret_store_t *store) {
  size_t i;
  if (store == 0) {
    return;
  }
  store->count = 0u;
  for (i = 0; i < 128u; ++i) {
    store->entries[i].key[0] = '\0';
    memset(store->entries[i].value, 0, sizeof(store->entries[i].value));
    store->entries[i].value_size = 0u;
    store->entries[i].created_at_epoch = 0u;
    store->entries[i].updated_at_epoch = 0u;
    store->entries[i].active = 0u;
  }
}

int aegis_secret_put(aegis_secret_store_t *store,
                     const char *key,
                     const uint8_t *value,
                     uint32_t value_size) {
  return aegis_secret_put_at(store, key, value, value_size, 0u);
}

int aegis_secret_put_at(aegis_secret_store_t *store,
                        const char *key,
                        const uint8_t *value,
                        uint32_t value_size,
                        uint64_t now_epoch) {
  size_t i;
  size_t index = 0u;
  if (store == 0 || !secret_key_valid(key) || value == 0 || value_size == 0u || value_size > 64u) {
    return -1;
  }
  if (secret_find_index(store, key, &index)) {
    memcpy(store->entries[index].value, value, value_size);
    if (value_size < 64u) {
      memset(store->entries[index].value + value_size, 0, (size_t)(64u - value_size));
    }
    store->entries[index].value_size = value_size;
    if (store->entries[index].created_at_epoch == 0u) {
      store->entries[index].created_at_epoch = now_epoch;
    }
    store->entries[index].updated_at_epoch = now_epoch;
    return 0;
  }
  if (store->count >= 128u) {
    return -1;
  }
  for (i = 0; i < 128u; ++i) {
    if (store->entries[i].active != 0u) {
      continue;
    }
    snprintf(store->entries[i].key, sizeof(store->entries[i].key), "%s", key);
    memcpy(store->entries[i].value, value, value_size);
    if (value_size < 64u) {
      memset(store->entries[i].value + value_size, 0, (size_t)(64u - value_size));
    }
    store->entries[i].value_size = value_size;
    store->entries[i].created_at_epoch = now_epoch;
    store->entries[i].updated_at_epoch = now_epoch;
    store->entries[i].active = 1u;
    store->count += 1u;
    return 0;
  }
  return -1;
}

int aegis_secret_get(const aegis_secret_store_t *store,
                     const char *key,
                     uint8_t *value_out,
                     uint32_t value_out_size,
                     uint32_t *value_size_out) {
  size_t index = 0u;
  uint32_t sz;
  if (store == 0 || key == 0 || value_out == 0 || value_size_out == 0) {
    return -1;
  }
  if (!secret_find_index(store, key, &index)) {
    return -1;
  }
  sz = store->entries[index].value_size;
  if (value_out_size < sz) {
    return -1;
  }
  memcpy(value_out, store->entries[index].value, sz);
  *value_size_out = sz;
  return 0;
}

int aegis_secret_metadata_get(const aegis_secret_store_t *store,
                              const char *key,
                              aegis_secret_metadata_t *metadata_out) {
  size_t index = 0u;
  if (store == 0 || key == 0 || metadata_out == 0) {
    return -1;
  }
  if (!secret_find_index(store, key, &index)) {
    return -1;
  }
  metadata_out->created_at_epoch = store->entries[index].created_at_epoch;
  metadata_out->updated_at_epoch = store->entries[index].updated_at_epoch;
  metadata_out->active = store->entries[index].active;
  return 0;
}

int aegis_secret_delete(aegis_secret_store_t *store, const char *key) {
  size_t index = 0u;
  if (store == 0 || key == 0) {
    return -1;
  }
  if (!secret_find_index(store, key, &index)) {
    return -1;
  }
  store->entries[index].active = 0u;
  store->entries[index].key[0] = '\0';
  memset(store->entries[index].value, 0, sizeof(store->entries[index].value));
  store->entries[index].value_size = 0u;
  store->entries[index].created_at_epoch = 0u;
  store->entries[index].updated_at_epoch = 0u;
  if (store->count > 0u) {
    store->count -= 1u;
  }
  return 0;
}

int aegis_secret_list_json(const aegis_secret_store_t *store, char *out, size_t out_size) {
  size_t i;
  size_t offset = 0u;
  int first = 1;
  int written;
  if (store == 0 || out == 0 || out_size == 0u) {
    return -1;
  }
  written = snprintf(out,
                     out_size,
                     "{\"schema_version\":1,\"count\":%llu,\"keys\":[",
                     (unsigned long long)store->count);
  if (written < 0 || (size_t)written >= out_size) {
    return -1;
  }
  offset = (size_t)written;
  for (i = 0; i < 128u; ++i) {
    if (store->entries[i].active == 0u) {
      continue;
    }
    written = snprintf(out + offset,
                       out_size - offset,
                       "%s\"%s\"",
                       first ? "" : ",",
                       store->entries[i].key);
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

int aegis_secret_snapshot_export(const aegis_secret_store_t *store, char *out, size_t out_size) {
  size_t i;
  size_t offset = 0u;
  char hex_value_buf[129];
  uint64_t digest = 0u;
  if (store == 0 || out == 0 || out_size == 0u) {
    return -1;
  }
  if (aegis_secret_snapshot_digest(store, &digest) != 0) {
    return -1;
  }
  out[0] = '\0';
  if (append_format(out, out_size, &offset, "schema_version=1\n") != 0) {
    return -1;
  }
  if (append_format(out, out_size, &offset, "digest=%016llx\n", (unsigned long long)digest) != 0) {
    return -1;
  }
  for (i = 0; i < 128u; ++i) {
    const aegis_secret_entry_t *entry = &store->entries[i];
    if (entry->active == 0u) {
      continue;
    }
    if (secret_value_to_hex(entry->value, entry->value_size, hex_value_buf, sizeof(hex_value_buf)) != 0) {
      return -1;
    }
    if (append_format(out,
                      out_size,
                      &offset,
                      "key=%s,size=%u,created=%llu,updated=%llu,value=%s\n",
                      entry->key,
                      entry->value_size,
                      (unsigned long long)entry->created_at_epoch,
                      (unsigned long long)entry->updated_at_epoch,
                      hex_value_buf) != 0) {
      return -1;
    }
  }
  return (int)offset;
}

int aegis_secret_snapshot_digest(const aegis_secret_store_t *store, uint64_t *digest_out) {
  size_t i;
  uint64_t digest = 1469598103934665603ull;
  if (store == 0 || digest_out == 0) {
    return -1;
  }
  for (i = 0; i < 128u; ++i) {
    const aegis_secret_entry_t *entry = &store->entries[i];
    uint64_t fp;
    if (entry->active == 0u) {
      continue;
    }
    fp = secret_fingerprint64(entry->key, entry->value, entry->value_size);
    digest ^= fp;
    digest *= 1099511628211ull;
    digest ^= entry->created_at_epoch;
    digest *= 1099511628211ull;
    digest ^= entry->updated_at_epoch;
    digest *= 1099511628211ull;
  }
  *digest_out = digest;
  return 0;
}

int aegis_secret_snapshot_restore(aegis_secret_store_t *store, const char *snapshot) {
  const char *cursor;
  size_t snapshot_bytes = 0u;
  size_t line_count = 0u;
  size_t record_count = 0u;
  int has_expected_digest = 0;
  uint64_t expected_digest = 0u;
  if (store == 0 || snapshot == 0) {
    return -1;
  }
  snapshot_bytes = strlen(snapshot);
  if (snapshot_bytes == 0u || snapshot_bytes > AEGIS_SECRET_SNAPSHOT_MAX_BYTES) {
    return -1;
  }
  aegis_secret_store_init(store);
  cursor = snapshot;
  {
    char header[64];
    size_t hlen = 0u;
    while (cursor[hlen] != '\0' && cursor[hlen] != '\n') {
      hlen += 1u;
    }
    if (hlen == 0u || hlen >= sizeof(header)) {
      return -1;
    }
    memcpy(header, cursor, hlen);
    header[hlen] = '\0';
    if (strcmp(header, "schema_version=1") != 0) {
      return -1;
    }
    cursor += hlen;
    if (*cursor == '\n') {
      cursor++;
    }
  }
  if (strncmp(cursor, "digest=", 7) == 0) {
    char digest_hex[32];
    const char *line_start = cursor + 7;
    size_t len = 0u;
    while (line_start[len] != '\0' && line_start[len] != '\n') {
      len++;
    }
    if (len == 0u || len >= sizeof(digest_hex)) {
      return -1;
    }
    memcpy(digest_hex, line_start, len);
    digest_hex[len] = '\0';
    if (parse_u64_hex(digest_hex, &expected_digest) != 0) {
      return -1;
    }
    has_expected_digest = 1;
    cursor = line_start + len;
    if (*cursor == '\n') {
      cursor++;
    }
  }
  while (*cursor != '\0') {
    char line[320];
    const char *line_start = cursor;
    size_t len = 0u;
    char key[32];
    unsigned int size_u = 0u;
    unsigned long long created_u = 0ull;
    unsigned long long updated_u = 0ull;
    char hex_payload[129];
    uint8_t value[64];
    uint32_t value_size = 0u;
    size_t slot = 0u;
    while (*cursor != '\0' && *cursor != '\n') {
      cursor++;
    }
    len = (size_t)(cursor - line_start);
    if (*cursor == '\n') {
      cursor++;
    }
    line_count += 1u;
    if (line_count > AEGIS_SECRET_SNAPSHOT_MAX_LINES) {
      return -1;
    }
    if (len == 0u) {
      continue;
    }
    if (len >= sizeof(line)) {
      return -1;
    }
    memcpy(line, line_start, len);
    line[len] = '\0';
    if (strncmp(line, "key=", 4) != 0) {
      return -1;
    }
    record_count += 1u;
    if (record_count > 128u) {
      return -1;
    }
    key[0] = '\0';
    hex_payload[0] = '\0';
    if (sscanf(line, "key=%31[^,],size=%u,created=%llu,updated=%llu,value=%128s",
               key, &size_u, &created_u, &updated_u, hex_payload) != 5) {
      return -1;
    }
    if (!secret_key_valid(key) || size_u == 0u || size_u > 64u) {
      return -1;
    }
    if (secret_hex_to_value(hex_payload, value, 64u, &value_size) != 0 || value_size != size_u) {
      return -1;
    }
    if (secret_find_index(store, key, &slot)) {
      return -1;
    }
    if (store->count >= 128u) {
      return -1;
    }
    for (slot = 0u; slot < 128u; ++slot) {
      if (store->entries[slot].active == 0u) {
        break;
      }
    }
    if (slot >= 128u) {
      return -1;
    }
    snprintf(store->entries[slot].key, sizeof(store->entries[slot].key), "%s", key);
    memcpy(store->entries[slot].value, value, value_size);
    if (value_size < 64u) {
      memset(store->entries[slot].value + value_size, 0, (size_t)(64u - value_size));
    }
    store->entries[slot].value_size = value_size;
    store->entries[slot].created_at_epoch = (uint64_t)created_u;
    store->entries[slot].updated_at_epoch = (uint64_t)updated_u;
    store->entries[slot].active = 1u;
    store->count += 1u;
  }
  if (has_expected_digest != 0) {
    uint64_t actual_digest = 0u;
    if (aegis_secret_snapshot_digest(store, &actual_digest) != 0 || actual_digest != expected_digest) {
      aegis_secret_store_init(store);
      return -1;
    }
  }
  return (int)store->count;
}

int aegis_secret_inventory_json(const aegis_secret_store_t *store, char *out, size_t out_size) {
  size_t i;
  size_t j;
  size_t active_count = 0u;
  size_t active_indices[128];
  size_t offset = 0u;
  int first = 1;
  if (store == 0 || out == 0 || out_size == 0u) {
    return -1;
  }
  out[0] = '\0';
  if (append_format(out,
                    out_size,
                    &offset,
                    "{\"schema_version\":1,\"count\":%llu,\"entries\":[",
                    (unsigned long long)store->count) != 0) {
    return -1;
  }
  for (i = 0; i < 128u; ++i) {
    if (store->entries[i].active != 0u) {
      active_indices[active_count] = i;
      active_count += 1u;
    }
  }
  for (i = 1u; i < active_count; ++i) {
    size_t key_index = active_indices[i];
    j = i;
    while (j > 0u &&
           strcmp(store->entries[active_indices[j - 1u]].key, store->entries[key_index].key) > 0) {
      active_indices[j] = active_indices[j - 1u];
      j -= 1u;
    }
    active_indices[j] = key_index;
  }
  for (i = 0u; i < active_count; ++i) {
    size_t idx = active_indices[i];
    const aegis_secret_entry_t *entry = &store->entries[i];
    uint64_t fp;
    entry = &store->entries[idx];
    fp = secret_fingerprint64(entry->key, entry->value, entry->value_size);
    if (!first) {
      if (append_format(out, out_size, &offset, ",") != 0) {
        return -1;
      }
    }
    if (append_format(out,
                      out_size,
                      &offset,
                      "{\"key\":\"%s\",\"value_size\":%u,\"created_at_epoch\":%llu,"
                      "\"updated_at_epoch\":%llu,\"fingerprint64\":\"%016llx\"}",
                      entry->key,
                      entry->value_size,
                      (unsigned long long)entry->created_at_epoch,
                      (unsigned long long)entry->updated_at_epoch,
                      (unsigned long long)fp) != 0) {
      return -1;
    }
    first = 0;
  }
  if (append_format(out, out_size, &offset, "]}") != 0) {
    return -1;
  }
  return (int)offset;
}
