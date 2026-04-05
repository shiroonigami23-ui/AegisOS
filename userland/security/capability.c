#include "capability.h"

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

static aegis_capability_audit_event_t g_audit_events[512];
static size_t g_audit_count = 0;
static aegis_actor_registry_entry_t g_actor_registry[256];

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
