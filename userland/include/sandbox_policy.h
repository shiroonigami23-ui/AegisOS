#ifndef AEGIS_SANDBOX_POLICY_H
#define AEGIS_SANDBOX_POLICY_H

#include <stddef.h>
#include <stdint.h>

#include "capability.h"

#define AEGIS_SANDBOX_POLICY_SCHEMA_VERSION 1u

typedef struct {
  uint32_t process_id;
  uint32_t capabilities;
  uint8_t allow_fs_read;
  uint8_t allow_fs_write;
  uint8_t allow_net_client;
  uint8_t allow_net_server;
  uint8_t allow_device_io;
  uint32_t schema_version;
  uint64_t policy_revision;
} aegis_sandbox_policy_t;

typedef struct {
  uint8_t migrated;
  uint32_t from_schema_version;
  uint32_t to_schema_version;
  uint64_t assigned_policy_revision;
} aegis_sandbox_policy_migration_report_t;

typedef struct {
  uint64_t timestamp_epoch;
  uint32_t process_id;
  uint64_t before_revision;
  uint64_t after_revision;
  uint32_t added_capability_mask;
  uint32_t removed_capability_mask;
  uint32_t changed_gate_mask;
  char actor[32];
  char reason[64];
} aegis_permission_center_audit_event_t;

int aegis_sandbox_policy_validate(const aegis_sandbox_policy_t *policy,
                                  char *reason, size_t reason_size);
int aegis_sandbox_policy_allows(const aegis_sandbox_policy_t *policy,
                                uint32_t capability_bit);
int aegis_sandbox_policy_serialize_json(const aegis_sandbox_policy_t *policy,
                                        char *output, size_t output_size);
int aegis_sandbox_policy_deserialize_json(const char *input,
                                          aegis_sandbox_policy_t *policy,
                                          char *reason, size_t reason_size);
int aegis_sandbox_policy_migrate_legacy_json(const char *legacy_input,
                                             char *output, size_t output_size,
                                             aegis_sandbox_policy_migration_report_t *report,
                                             char *reason, size_t reason_size);
int aegis_permission_center_policy_summary_json(const aegis_sandbox_policy_t *policy,
                                                char *output, size_t output_size);
int aegis_permission_center_policy_diff_json(const aegis_sandbox_policy_t *before_policy,
                                             const aegis_sandbox_policy_t *after_policy,
                                             char *output,
                                             size_t output_size);
void aegis_permission_center_audit_reset(void);
size_t aegis_permission_center_audit_count(void);
int aegis_permission_center_record_policy_change(const aegis_sandbox_policy_t *before_policy,
                                                 const aegis_sandbox_policy_t *after_policy,
                                                 uint64_t now_epoch,
                                                 const char *actor,
                                                 const char *reason);
int aegis_permission_center_audit_export_json(char *output, size_t output_size);
int aegis_permission_center_audit_export_csv(char *output, size_t output_size);

#endif
