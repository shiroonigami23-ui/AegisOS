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

typedef enum {
  AEGIS_PERMISSION_APPROVAL_PENDING = 1,
  AEGIS_PERMISSION_APPROVAL_APPROVED = 2,
  AEGIS_PERMISSION_APPROVAL_REJECTED = 3
} aegis_permission_approval_status_t;

typedef struct {
  uint64_t request_id;
  uint64_t created_epoch;
  uint64_t resolved_epoch;
  uint32_t process_id;
  uint8_t status;
  aegis_sandbox_policy_t before_policy;
  aegis_sandbox_policy_t proposed_policy;
  char requested_by[32];
  char rationale[96];
  char resolved_by[32];
  char resolution_note[96];
  uint32_t risk_score;
  uint8_t requires_security_review;
} aegis_permission_change_request_t;

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
void aegis_permission_center_approval_reset(void);
size_t aegis_permission_center_approval_count(void);
size_t aegis_permission_center_approval_pending_count(void);
int aegis_permission_center_submit_change_request(const aegis_sandbox_policy_t *before_policy,
                                                  const aegis_sandbox_policy_t *proposed_policy,
                                                  uint64_t now_epoch,
                                                  const char *requested_by,
                                                  const char *rationale,
                                                  uint64_t *request_id_out);
int aegis_permission_center_approve_change_request(uint64_t request_id,
                                                   uint64_t now_epoch,
                                                   const char *resolved_by,
                                                   const char *note,
                                                   aegis_sandbox_policy_t *applied_policy_out);
int aegis_permission_center_reject_change_request(uint64_t request_id,
                                                  uint64_t now_epoch,
                                                  const char *resolved_by,
                                                  const char *note);
int aegis_permission_center_approval_export_json(char *output, size_t output_size);
int aegis_permission_center_approval_metrics_json(char *output, size_t output_size);

#endif
