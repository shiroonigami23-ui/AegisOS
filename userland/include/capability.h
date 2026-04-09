#ifndef AEGIS_CAPABILITY_H
#define AEGIS_CAPABILITY_H

#include <stdint.h>
#include <stddef.h>

typedef enum {
  AEGIS_CAP_NONE = 0,
  AEGIS_CAP_FS_READ = 1u << 0,
  AEGIS_CAP_FS_WRITE = 1u << 1,
  AEGIS_CAP_NET_CLIENT = 1u << 2,
  AEGIS_CAP_NET_SERVER = 1u << 3,
  AEGIS_CAP_DEVICE_IO = 1u << 4
} aegis_capability_bits_t;

typedef struct {
  uint32_t process_id;
  uint32_t permissions;
  uint64_t issued_at_epoch;
  uint64_t expires_at_epoch;
  uint64_t rotation_counter;
} aegis_capability_token_t;

typedef struct {
  aegis_capability_token_t tokens[128];
  uint8_t active[128];
  size_t count;
} aegis_capability_store_t;

typedef enum {
  AEGIS_CAP_AUDIT_ISSUE = 1,
  AEGIS_CAP_AUDIT_ROTATE = 2,
  AEGIS_CAP_AUDIT_REVOKE = 3,
  AEGIS_CAP_AUDIT_ALLOW = 4,
  AEGIS_CAP_AUDIT_DENY = 5
} aegis_capability_audit_event_type_t;

typedef enum {
  AEGIS_ACTOR_SYSTEM = 1,
  AEGIS_ACTOR_USER = 2,
  AEGIS_ACTOR_SERVICE = 3,
  AEGIS_ACTOR_AUTOMATION = 4
} aegis_actor_source_t;

typedef struct {
  uint64_t timestamp_epoch;
  uint32_t process_id;
  uint32_t requested_permissions;
  uint32_t resulting_permissions;
  uint32_t actor_id;
  uint8_t actor_source;
  char actor_label[32];
  char reason[64];
  uint8_t event_type;
} aegis_capability_audit_event_t;

typedef struct {
  size_t next_cursor;
  size_t exported_count;
  uint8_t has_more;
} aegis_capability_audit_page_t;

typedef struct {
  uint64_t total_events;
  uint64_t issue_events;
  uint64_t rotate_events;
  uint64_t revoke_events;
  uint64_t allow_events;
  uint64_t deny_events;
} aegis_capability_audit_summary_t;

typedef struct {
  uint32_t latest_chunk_id;
  uint32_t retention_window_chunks;
  uint32_t keep_from_chunk_id;
  uint32_t keep_to_chunk_id;
  uint32_t prune_chunk_count;
} aegis_capability_audit_retention_plan_t;

typedef struct {
  uint32_t actor_id;
  uint8_t actor_source;
  char actor_label[32];
  uint8_t active;
  uint8_t revoked;
  uint64_t revoked_at_epoch;
} aegis_actor_registry_entry_t;

typedef struct {
  char key[32];
  uint8_t value[64];
  uint32_t value_size;
  uint64_t created_at_epoch;
  uint64_t updated_at_epoch;
  uint8_t active;
} aegis_secret_entry_t;

typedef struct {
  aegis_secret_entry_t entries[128];
  size_t count;
} aegis_secret_store_t;

typedef struct {
  uint64_t created_at_epoch;
  uint64_t updated_at_epoch;
  uint8_t active;
} aegis_secret_metadata_t;

int aegis_capability_validate(const aegis_capability_token_t *token,
                              uint32_t requested_permissions);
void aegis_capability_store_init(aegis_capability_store_t *store);
int aegis_capability_issue(aegis_capability_store_t *store, uint32_t process_id,
                           uint32_t permissions);
int aegis_capability_issue_with_ttl(aegis_capability_store_t *store, uint32_t process_id,
                                    uint32_t permissions, uint64_t now_epoch,
                                    uint64_t ttl_seconds);
int aegis_capability_rotate(aegis_capability_store_t *store, uint32_t process_id,
                            uint32_t permissions, uint64_t now_epoch, uint64_t ttl_seconds);
int aegis_capability_rotate_with_metadata(aegis_capability_store_t *store, uint32_t process_id,
                                          uint32_t permissions, uint64_t now_epoch,
                                          uint64_t ttl_seconds, uint32_t actor_id,
                                          const char *reason);
int aegis_capability_rotate_with_identity(aegis_capability_store_t *store, uint32_t process_id,
                                          uint32_t permissions, uint64_t now_epoch,
                                          uint64_t ttl_seconds, uint32_t actor_id,
                                          uint8_t actor_source, const char *actor_label,
                                          const char *reason);
int aegis_capability_revoke(aegis_capability_store_t *store, uint32_t process_id);
int aegis_capability_revoke_with_identity(aegis_capability_store_t *store, uint32_t process_id,
                                          uint64_t now_epoch, uint32_t actor_id,
                                          uint8_t actor_source, const char *actor_label,
                                          const char *reason);
int aegis_capability_is_allowed(const aegis_capability_store_t *store, uint32_t process_id,
                                uint32_t requested_permissions);
int aegis_capability_is_allowed_at(const aegis_capability_store_t *store, uint32_t process_id,
                                   uint32_t requested_permissions, uint64_t now_epoch);
void aegis_capability_audit_reset(void);
size_t aegis_capability_audit_count(void);
int aegis_capability_audit_get(size_t index, aegis_capability_audit_event_t *event);
int aegis_capability_audit_export_json(char *out, size_t out_size);
int aegis_capability_audit_export_csv(char *out, size_t out_size);
int aegis_capability_audit_summary_snapshot(aegis_capability_audit_summary_t *summary);
int aegis_capability_audit_summary_json(char *out, size_t out_size);
int aegis_capability_audit_export_json_page(size_t cursor, size_t limit,
                                            char *out, size_t out_size,
                                            aegis_capability_audit_page_t *page);
int aegis_capability_audit_export_csv_page(size_t cursor, size_t limit,
                                           char *out, size_t out_size,
                                           aegis_capability_audit_page_t *page);
size_t aegis_capability_audit_cursor_for_timestamp(uint64_t timestamp_epoch);
int aegis_capability_audit_file_sink_name(const char *prefix, uint32_t chunk_id,
                                          char *out, size_t out_size);
int aegis_capability_audit_retention_plan(uint32_t latest_chunk_id,
                                          uint32_t retention_window_chunks,
                                          aegis_capability_audit_retention_plan_t *plan);
int aegis_capability_audit_prune_candidate_name(const char *prefix,
                                                uint32_t latest_chunk_id,
                                                uint32_t retention_window_chunks,
                                                uint32_t prune_index,
                                                char *out,
                                                size_t out_size);
void aegis_actor_registry_reset(void);
int aegis_actor_registry_register(uint32_t actor_id, uint8_t actor_source, const char *actor_label);
int aegis_actor_registry_lookup(uint32_t actor_id, uint8_t actor_source,
                                aegis_actor_registry_entry_t *entry);
int aegis_actor_registry_revoke(uint32_t actor_id, uint8_t actor_source,
                                uint64_t now_epoch, const char *reason);
int aegis_actor_registry_snapshot(char *out, size_t out_size);
int aegis_actor_registry_restore(const char *snapshot);
void aegis_secret_store_init(aegis_secret_store_t *store);
int aegis_secret_put(aegis_secret_store_t *store,
                     const char *key,
                     const uint8_t *value,
                     uint32_t value_size);
int aegis_secret_put_at(aegis_secret_store_t *store,
                        const char *key,
                        const uint8_t *value,
                        uint32_t value_size,
                        uint64_t now_epoch);
int aegis_secret_get(const aegis_secret_store_t *store,
                     const char *key,
                     uint8_t *value_out,
                     uint32_t value_out_size,
                     uint32_t *value_size_out);
int aegis_secret_metadata_get(const aegis_secret_store_t *store,
                              const char *key,
                              aegis_secret_metadata_t *metadata_out);
int aegis_secret_delete(aegis_secret_store_t *store, const char *key);
int aegis_secret_list_json(const aegis_secret_store_t *store, char *out, size_t out_size);
int aegis_secret_snapshot_digest(const aegis_secret_store_t *store, uint64_t *digest_out);
int aegis_secret_snapshot_export(const aegis_secret_store_t *store, char *out, size_t out_size);
int aegis_secret_snapshot_restore(aegis_secret_store_t *store, const char *snapshot);
int aegis_secret_inventory_json(const aegis_secret_store_t *store, char *out, size_t out_size);

#endif
