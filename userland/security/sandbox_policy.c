#include "sandbox_policy.h"

#include <stdio.h>
#include <string.h>

static aegis_permission_center_audit_event_t g_permission_center_audit[256];
static size_t g_permission_center_audit_count = 0u;
static aegis_permission_change_request_t g_permission_center_requests[256];
static size_t g_permission_center_request_count = 0u;
static uint64_t g_permission_center_next_request_id = 1u;

static void write_reason(char *reason, size_t reason_size, const char *message) {
  if (reason == 0 || reason_size == 0 || message == 0) {
    return;
  }
  snprintf(reason, reason_size, "%s", message);
}

static uint32_t policy_schema_version(const aegis_sandbox_policy_t *policy) {
  if (policy->schema_version == 0u) {
    return AEGIS_SANDBOX_POLICY_SCHEMA_VERSION;
  }
  return policy->schema_version;
}

static uint64_t policy_revision(const aegis_sandbox_policy_t *policy) {
  if (policy->policy_revision == 0u) {
    return 1u;
  }
  return policy->policy_revision;
}

static int extract_u64_json_field(const char *input,
                                  const char *field_name,
                                  int required,
                                  uint64_t *value_out) {
  const char *cursor;
  char key[64];
  uint64_t value = 0u;
  int found_digit = 0;
  if (input == 0 || field_name == 0 || value_out == 0) {
    return -1;
  }
  snprintf(key, sizeof(key), "\"%s\":", field_name);
  cursor = strstr(input, key);
  if (cursor == 0) {
    return required ? -1 : 0;
  }
  cursor += strlen(key);
  while (*cursor == ' ' || *cursor == '\t' || *cursor == '\n' || *cursor == '\r') {
    cursor++;
  }
  while (*cursor >= '0' && *cursor <= '9') {
    found_digit = 1;
    value = (value * 10u) + (uint64_t)(*cursor - '0');
    cursor++;
  }
  if (!found_digit) {
    return -1;
  }
  *value_out = value;
  return 1;
}

int aegis_sandbox_policy_validate(const aegis_sandbox_policy_t *policy,
                                  char *reason, size_t reason_size) {
  const uint32_t known_mask = AEGIS_CAP_FS_READ | AEGIS_CAP_FS_WRITE | AEGIS_CAP_NET_CLIENT |
                              AEGIS_CAP_NET_SERVER | AEGIS_CAP_DEVICE_IO;
  if (reason != 0 && reason_size > 0) {
    reason[0] = '\0';
  }
  if (policy == 0) {
    write_reason(reason, reason_size, "policy is null");
    return 0;
  }
  if (policy->process_id == 0) {
    write_reason(reason, reason_size, "process_id must be non-zero");
    return 0;
  }
  if ((policy->capabilities & ~known_mask) != 0) {
    write_reason(reason, reason_size, "policy includes unknown capability bits");
    return 0;
  }
  if (policy_schema_version(policy) != AEGIS_SANDBOX_POLICY_SCHEMA_VERSION) {
    write_reason(reason, reason_size, "unsupported sandbox policy schema_version");
    return 0;
  }
  if ((policy->allow_fs_read != 0) && ((policy->capabilities & AEGIS_CAP_FS_READ) == 0)) {
    write_reason(reason, reason_size, "allow_fs_read set but FS_READ capability missing");
    return 0;
  }
  if ((policy->allow_fs_write != 0) && ((policy->capabilities & AEGIS_CAP_FS_WRITE) == 0)) {
    write_reason(reason, reason_size, "allow_fs_write set but FS_WRITE capability missing");
    return 0;
  }
  if ((policy->allow_net_client != 0) && ((policy->capabilities & AEGIS_CAP_NET_CLIENT) == 0)) {
    write_reason(reason, reason_size, "allow_net_client set but NET_CLIENT capability missing");
    return 0;
  }
  if ((policy->allow_net_server != 0) && ((policy->capabilities & AEGIS_CAP_NET_SERVER) == 0)) {
    write_reason(reason, reason_size, "allow_net_server set but NET_SERVER capability missing");
    return 0;
  }
  if ((policy->allow_device_io != 0) && ((policy->capabilities & AEGIS_CAP_DEVICE_IO) == 0)) {
    write_reason(reason, reason_size, "allow_device_io set but DEVICE_IO capability missing");
    return 0;
  }
  if (policy->allow_net_server != 0 && policy->allow_net_client == 0) {
    write_reason(reason, reason_size, "server mode requires client networking enabled");
    return 0;
  }
  write_reason(reason, reason_size, "ok");
  return 1;
}

int aegis_sandbox_policy_allows(const aegis_sandbox_policy_t *policy,
                                uint32_t capability_bit) {
  char reason[64];
  if (!aegis_sandbox_policy_validate(policy, reason, sizeof(reason))) {
    return 0;
  }
  return (policy->capabilities & capability_bit) == capability_bit;
}

int aegis_sandbox_policy_serialize_json(const aegis_sandbox_policy_t *policy,
                                        char *output, size_t output_size) {
  int written;
  char reason[64];
  if (output == 0 || output_size == 0 || policy == 0) {
    return -1;
  }
  if (!aegis_sandbox_policy_validate(policy, reason, sizeof(reason))) {
    return -1;
  }
  written = snprintf(
      output,
      output_size,
      "{\"process_id\":%u,\"capabilities\":%u,\"allow_fs_read\":%u,"
      "\"allow_fs_write\":%u,\"allow_net_client\":%u,\"allow_net_server\":%u,"
      "\"schema_version\":%u,\"policy_revision\":%llu,"
      "\"allow_device_io\":%u}",
      policy->process_id,
      policy->capabilities,
      (unsigned int)policy->allow_fs_read,
      (unsigned int)policy->allow_fs_write,
      (unsigned int)policy->allow_net_client,
      (unsigned int)policy->allow_net_server,
      (unsigned int)policy_schema_version(policy),
      (unsigned long long)policy_revision(policy),
      (unsigned int)policy->allow_device_io);
  if (written < 0 || (size_t)written >= output_size) {
    return -1;
  }
  return 0;
}

int aegis_sandbox_policy_deserialize_json(const char *input,
                                          aegis_sandbox_policy_t *policy,
                                          char *reason, size_t reason_size) {
  uint64_t process_id = 0u;
  uint64_t capabilities = 0u;
  uint64_t allow_fs_read = 0u;
  uint64_t allow_fs_write = 0u;
  uint64_t allow_net_client = 0u;
  uint64_t allow_net_server = 0u;
  uint64_t schema_version = 0u;
  uint64_t policy_rev = 0u;
  uint64_t allow_device_io = 0u;
  int rc;
  if (reason != 0 && reason_size > 0) {
    reason[0] = '\0';
  }
  if (input == 0 || policy == 0) {
    write_reason(reason, reason_size, "input or policy is null");
    return -1;
  }
  rc = extract_u64_json_field(input, "process_id", 1, &process_id);
  if (rc != 1) {
    write_reason(reason, reason_size, "invalid sandbox policy JSON format");
    return -1;
  }
  rc = extract_u64_json_field(input, "capabilities", 1, &capabilities);
  if (rc != 1) {
    write_reason(reason, reason_size, "invalid sandbox policy JSON format");
    return -1;
  }
  rc = extract_u64_json_field(input, "allow_fs_read", 1, &allow_fs_read);
  if (rc != 1) {
    write_reason(reason, reason_size, "invalid sandbox policy JSON format");
    return -1;
  }
  rc = extract_u64_json_field(input, "allow_fs_write", 1, &allow_fs_write);
  if (rc != 1) {
    write_reason(reason, reason_size, "invalid sandbox policy JSON format");
    return -1;
  }
  rc = extract_u64_json_field(input, "allow_net_client", 1, &allow_net_client);
  if (rc != 1) {
    write_reason(reason, reason_size, "invalid sandbox policy JSON format");
    return -1;
  }
  rc = extract_u64_json_field(input, "allow_net_server", 1, &allow_net_server);
  if (rc != 1) {
    write_reason(reason, reason_size, "invalid sandbox policy JSON format");
    return -1;
  }
  rc = extract_u64_json_field(input, "allow_device_io", 1, &allow_device_io);
  if (rc != 1) {
    write_reason(reason, reason_size, "invalid sandbox policy JSON format");
    return -1;
  }
  rc = extract_u64_json_field(input, "schema_version", 0, &schema_version);
  if (rc < 0) {
    write_reason(reason, reason_size, "invalid sandbox policy JSON format");
    return -1;
  }
  if (rc == 0) {
    schema_version = AEGIS_SANDBOX_POLICY_SCHEMA_VERSION;
  }
  rc = extract_u64_json_field(input, "policy_revision", 0, &policy_rev);
  if (rc < 0) {
    write_reason(reason, reason_size, "invalid sandbox policy JSON format");
    return -1;
  }
  if (rc == 0) {
    policy_rev = 1u;
  }
  if (process_id > 0xFFFFFFFFu || capabilities > 0xFFFFFFFFu ||
      allow_fs_read > 0xFFu || allow_fs_write > 0xFFu ||
      allow_net_client > 0xFFu || allow_net_server > 0xFFu ||
      allow_device_io > 0xFFu || schema_version > 0xFFFFFFFFu) {
    write_reason(reason, reason_size, "sandbox policy JSON numeric field out of range");
    return -1;
  }
  policy->process_id = (uint32_t)process_id;
  policy->capabilities = (uint32_t)capabilities;
  policy->schema_version = (uint32_t)schema_version;
  policy->policy_revision = policy_rev;
  policy->allow_fs_read = (uint8_t)allow_fs_read;
  policy->allow_fs_write = (uint8_t)allow_fs_write;
  policy->allow_net_client = (uint8_t)allow_net_client;
  policy->allow_net_server = (uint8_t)allow_net_server;
  policy->allow_device_io = (uint8_t)allow_device_io;
  if (!aegis_sandbox_policy_validate(policy, reason, reason_size)) {
    return -1;
  }
  return 0;
}

int aegis_sandbox_policy_migrate_legacy_json(const char *legacy_input,
                                             char *output, size_t output_size,
                                             aegis_sandbox_policy_migration_report_t *report,
                                             char *reason, size_t reason_size) {
  aegis_sandbox_policy_t policy;
  unsigned int process_id = 0;
  unsigned int capabilities = 0;
  unsigned int allow_fs_read = 0;
  unsigned int allow_fs_write = 0;
  unsigned int allow_net_client = 0;
  unsigned int allow_net_server = 0;
  unsigned int allow_device_io = 0;
  int matched = 0;

  if (reason != 0 && reason_size > 0) {
    reason[0] = '\0';
  }
  if (report != 0) {
    report->migrated = 0;
    report->from_schema_version = 0u;
    report->to_schema_version = AEGIS_SANDBOX_POLICY_SCHEMA_VERSION;
    report->assigned_policy_revision = 0u;
  }
  if (legacy_input == 0 || output == 0 || output_size == 0u) {
    write_reason(reason, reason_size, "legacy input or output is null");
    return -1;
  }

  matched = sscanf(
      legacy_input,
      "{\"process_id\":%u,\"capabilities\":%u,\"allow_fs_read\":%u,"
      "\"allow_fs_write\":%u,\"allow_net_client\":%u,\"allow_net_server\":%u,"
      "\"allow_device_io\":%u}",
      &process_id,
      &capabilities,
      &allow_fs_read,
      &allow_fs_write,
      &allow_net_client,
      &allow_net_server,
      &allow_device_io);
  if (matched != 7) {
    write_reason(reason, reason_size, "legacy JSON format not recognized");
    return -1;
  }

  policy.process_id = process_id;
  policy.capabilities = capabilities;
  policy.allow_fs_read = (uint8_t)allow_fs_read;
  policy.allow_fs_write = (uint8_t)allow_fs_write;
  policy.allow_net_client = (uint8_t)allow_net_client;
  policy.allow_net_server = (uint8_t)allow_net_server;
  policy.allow_device_io = (uint8_t)allow_device_io;
  policy.schema_version = AEGIS_SANDBOX_POLICY_SCHEMA_VERSION;
  policy.policy_revision = 1u;

  if (!aegis_sandbox_policy_validate(&policy, reason, reason_size)) {
    return -1;
  }
  if (aegis_sandbox_policy_serialize_json(&policy, output, output_size) != 0) {
    write_reason(reason, reason_size, "failed to serialize migrated policy");
    return -1;
  }
  if (report != 0) {
    report->migrated = 1u;
    report->from_schema_version = 0u;
    report->to_schema_version = AEGIS_SANDBOX_POLICY_SCHEMA_VERSION;
    report->assigned_policy_revision = 1u;
  }
  write_reason(reason, reason_size, "migrated");
  return 0;
}

int aegis_permission_center_policy_summary_json(const aegis_sandbox_policy_t *policy,
                                                char *output, size_t output_size) {
  int written;
  char reason[64];
  uint32_t caps = 0u;
  if (policy == 0 || output == 0 || output_size == 0u) {
    return -1;
  }
  if (!aegis_sandbox_policy_validate(policy, reason, sizeof(reason))) {
    return -1;
  }
  caps = policy->capabilities;
  written = snprintf(
      output,
      output_size,
      "{\"schema_version\":%u,\"process_id\":%u,\"policy_revision\":%llu,"
      "\"capability_mask\":%u,"
      "\"capabilities\":{\"fs_read\":%u,\"fs_write\":%u,\"net_client\":%u,"
      "\"net_server\":%u,\"device_io\":%u},"
      "\"actions\":{\"fs.read\":\"%s\",\"fs.write\":\"%s\",\"net.connect\":\"%s\","
      "\"net.listen\":\"%s\",\"device.io\":\"%s\"}}",
      (unsigned int)policy_schema_version(policy),
      policy->process_id,
      (unsigned long long)policy_revision(policy),
      caps,
      (unsigned int)((caps & AEGIS_CAP_FS_READ) != 0u ? 1u : 0u),
      (unsigned int)((caps & AEGIS_CAP_FS_WRITE) != 0u ? 1u : 0u),
      (unsigned int)((caps & AEGIS_CAP_NET_CLIENT) != 0u ? 1u : 0u),
      (unsigned int)((caps & AEGIS_CAP_NET_SERVER) != 0u ? 1u : 0u),
      (unsigned int)((caps & AEGIS_CAP_DEVICE_IO) != 0u ? 1u : 0u),
      policy->allow_fs_read != 0u ? "allow" : "deny",
      policy->allow_fs_write != 0u ? "allow" : "deny",
      policy->allow_net_client != 0u ? "allow" : "deny",
      policy->allow_net_server != 0u ? "allow" : "deny",
      policy->allow_device_io != 0u ? "allow" : "deny");
  if (written < 0 || (size_t)written >= output_size) {
    return -1;
  }
  return 0;
}

static uint32_t permission_center_gate_mask(const aegis_sandbox_policy_t *policy) {
  uint32_t mask = 0u;
  if (policy == 0) {
    return 0u;
  }
  if (policy->allow_fs_read != 0u) {
    mask |= 1u << 0;
  }
  if (policy->allow_fs_write != 0u) {
    mask |= 1u << 1;
  }
  if (policy->allow_net_client != 0u) {
    mask |= 1u << 2;
  }
  if (policy->allow_net_server != 0u) {
    mask |= 1u << 3;
  }
  if (policy->allow_device_io != 0u) {
    mask |= 1u << 4;
  }
  return mask;
}

int aegis_permission_center_policy_diff_json(const aegis_sandbox_policy_t *before_policy,
                                             const aegis_sandbox_policy_t *after_policy,
                                             char *output,
                                             size_t output_size) {
  char reason[64];
  uint32_t before_caps;
  uint32_t after_caps;
  uint32_t added_caps;
  uint32_t removed_caps;
  uint32_t before_gates;
  uint32_t after_gates;
  uint32_t changed_gates;
  int written;
  if (before_policy == 0 || after_policy == 0 || output == 0 || output_size == 0u) {
    return -1;
  }
  if (!aegis_sandbox_policy_validate(before_policy, reason, sizeof(reason)) ||
      !aegis_sandbox_policy_validate(after_policy, reason, sizeof(reason))) {
    return -1;
  }
  if (before_policy->process_id != after_policy->process_id) {
    return -1;
  }
  before_caps = before_policy->capabilities;
  after_caps = after_policy->capabilities;
  added_caps = after_caps & (~before_caps);
  removed_caps = before_caps & (~after_caps);
  before_gates = permission_center_gate_mask(before_policy);
  after_gates = permission_center_gate_mask(after_policy);
  changed_gates = before_gates ^ after_gates;
  written = snprintf(
      output,
      output_size,
      "{\"schema_version\":1,\"process_id\":%u,\"before_revision\":%llu,"
      "\"after_revision\":%llu,\"added_capability_mask\":%u,\"removed_capability_mask\":%u,"
      "\"changed_gate_mask\":%u,\"before\":{\"capability_mask\":%u,\"gate_mask\":%u},"
      "\"after\":{\"capability_mask\":%u,\"gate_mask\":%u}}",
      after_policy->process_id,
      (unsigned long long)policy_revision(before_policy),
      (unsigned long long)policy_revision(after_policy),
      added_caps,
      removed_caps,
      changed_gates,
      before_caps,
      before_gates,
      after_caps,
      after_gates);
  if (written < 0 || (size_t)written >= output_size) {
    return -1;
  }
  return written;
}

void aegis_permission_center_audit_reset(void) {
  g_permission_center_audit_count = 0u;
}

size_t aegis_permission_center_audit_count(void) {
  return g_permission_center_audit_count;
}

int aegis_permission_center_record_policy_change(const aegis_sandbox_policy_t *before_policy,
                                                 const aegis_sandbox_policy_t *after_policy,
                                                 uint64_t now_epoch,
                                                 const char *actor,
                                                 const char *reason) {
  char validate_reason[64];
  size_t idx;
  uint32_t before_caps;
  uint32_t after_caps;
  uint32_t before_gates;
  uint32_t after_gates;
  if (before_policy == 0 || after_policy == 0) {
    return -1;
  }
  if (!aegis_sandbox_policy_validate(before_policy, validate_reason, sizeof(validate_reason)) ||
      !aegis_sandbox_policy_validate(after_policy, validate_reason, sizeof(validate_reason))) {
    return -1;
  }
  if (before_policy->process_id != after_policy->process_id) {
    return -1;
  }
  idx = g_permission_center_audit_count % 256u;
  before_caps = before_policy->capabilities;
  after_caps = after_policy->capabilities;
  before_gates = permission_center_gate_mask(before_policy);
  after_gates = permission_center_gate_mask(after_policy);
  g_permission_center_audit[idx].timestamp_epoch = now_epoch;
  g_permission_center_audit[idx].process_id = after_policy->process_id;
  g_permission_center_audit[idx].before_revision = policy_revision(before_policy);
  g_permission_center_audit[idx].after_revision = policy_revision(after_policy);
  g_permission_center_audit[idx].added_capability_mask = after_caps & (~before_caps);
  g_permission_center_audit[idx].removed_capability_mask = before_caps & (~after_caps);
  g_permission_center_audit[idx].changed_gate_mask = before_gates ^ after_gates;
  snprintf(g_permission_center_audit[idx].actor,
           sizeof(g_permission_center_audit[idx].actor),
           "%s",
           actor != 0 ? actor : "system");
  snprintf(g_permission_center_audit[idx].reason,
           sizeof(g_permission_center_audit[idx].reason),
           "%s",
           reason != 0 ? reason : "policy_change");
  g_permission_center_audit_count += 1u;
  return 0;
}

int aegis_permission_center_audit_export_json(char *output, size_t output_size) {
  size_t offset = 0u;
  size_t total = g_permission_center_audit_count > 256u ? 256u : g_permission_center_audit_count;
  size_t base = g_permission_center_audit_count > 256u ? g_permission_center_audit_count - 256u : 0u;
  size_t i;
  int written;
  if (output == 0 || output_size == 0u) {
    return -1;
  }
  written = snprintf(output, output_size, "[");
  if (written < 0 || (size_t)written >= output_size) {
    return -1;
  }
  offset = (size_t)written;
  for (i = 0; i < total; ++i) {
    size_t idx = (base + i) % 256u;
    const aegis_permission_center_audit_event_t *event = &g_permission_center_audit[idx];
    written = snprintf(output + offset,
                       output_size - offset,
                       "%s{\"timestamp_epoch\":%llu,\"process_id\":%u,\"before_revision\":%llu,"
                       "\"after_revision\":%llu,\"added_capability_mask\":%u,"
                       "\"removed_capability_mask\":%u,\"changed_gate_mask\":%u,"
                       "\"actor\":\"%s\",\"reason\":\"%s\"}",
                       i == 0u ? "" : ",",
                       (unsigned long long)event->timestamp_epoch,
                       event->process_id,
                       (unsigned long long)event->before_revision,
                       (unsigned long long)event->after_revision,
                       event->added_capability_mask,
                       event->removed_capability_mask,
                       event->changed_gate_mask,
                       event->actor,
                       event->reason);
    if (written < 0 || (size_t)written >= (output_size - offset)) {
      return -1;
    }
    offset += (size_t)written;
  }
  written = snprintf(output + offset, output_size - offset, "]");
  if (written < 0 || (size_t)written >= (output_size - offset)) {
    return -1;
  }
  offset += (size_t)written;
  return (int)offset;
}

int aegis_permission_center_audit_export_csv(char *output, size_t output_size) {
  size_t offset = 0u;
  size_t total = g_permission_center_audit_count > 256u ? 256u : g_permission_center_audit_count;
  size_t base = g_permission_center_audit_count > 256u ? g_permission_center_audit_count - 256u : 0u;
  size_t i;
  int written;
  if (output == 0 || output_size == 0u) {
    return -1;
  }
  written = snprintf(output,
                     output_size,
                     "timestamp_epoch,process_id,before_revision,after_revision,"
                     "added_capability_mask,removed_capability_mask,changed_gate_mask,actor,reason\n");
  if (written < 0 || (size_t)written >= output_size) {
    return -1;
  }
  offset = (size_t)written;
  for (i = 0; i < total; ++i) {
    size_t idx = (base + i) % 256u;
    const aegis_permission_center_audit_event_t *event = &g_permission_center_audit[idx];
    written = snprintf(output + offset,
                       output_size - offset,
                       "%llu,%u,%llu,%llu,%u,%u,%u,%s,%s\n",
                       (unsigned long long)event->timestamp_epoch,
                       event->process_id,
                       (unsigned long long)event->before_revision,
                       (unsigned long long)event->after_revision,
                       event->added_capability_mask,
                       event->removed_capability_mask,
                       event->changed_gate_mask,
                       event->actor,
                       event->reason);
    if (written < 0 || (size_t)written >= (output_size - offset)) {
      return -1;
    }
    offset += (size_t)written;
  }
  return (int)offset;
}

void aegis_permission_center_approval_reset(void) {
  g_permission_center_request_count = 0u;
  g_permission_center_next_request_id = 1u;
}

size_t aegis_permission_center_approval_count(void) {
  return g_permission_center_request_count;
}

size_t aegis_permission_center_approval_pending_count(void) {
  size_t i;
  size_t pending = 0u;
  size_t total =
      g_permission_center_request_count > 256u ? 256u : g_permission_center_request_count;
  size_t base =
      g_permission_center_request_count > 256u ? g_permission_center_request_count - 256u : 0u;
  for (i = 0; i < total; ++i) {
    size_t idx = (base + i) % 256u;
    if (g_permission_center_requests[idx].status == AEGIS_PERMISSION_APPROVAL_PENDING) {
      pending += 1u;
    }
  }
  return pending;
}

static int find_request_index_by_id(uint64_t request_id, size_t *index_out) {
  size_t i;
  size_t total =
      g_permission_center_request_count > 256u ? 256u : g_permission_center_request_count;
  size_t base =
      g_permission_center_request_count > 256u ? g_permission_center_request_count - 256u : 0u;
  if (request_id == 0u || index_out == 0) {
    return 0;
  }
  for (i = 0; i < total; ++i) {
    size_t idx = (base + i) % 256u;
    if (g_permission_center_requests[idx].request_id == request_id) {
      *index_out = idx;
      return 1;
    }
  }
  return 0;
}

static uint32_t capability_risk_score(uint32_t added_mask) {
  uint32_t score = 0u;
  if ((added_mask & AEGIS_CAP_FS_READ) != 0u) {
    score += 5u;
  }
  if ((added_mask & AEGIS_CAP_FS_WRITE) != 0u) {
    score += 10u;
  }
  if ((added_mask & AEGIS_CAP_NET_CLIENT) != 0u) {
    score += 15u;
  }
  if ((added_mask & AEGIS_CAP_NET_SERVER) != 0u) {
    score += 25u;
  }
  if ((added_mask & AEGIS_CAP_DEVICE_IO) != 0u) {
    score += 20u;
  }
  return score;
}

static uint32_t gate_risk_score(uint32_t changed_gate_mask) {
  uint32_t score = 0u;
  if ((changed_gate_mask & (1u << 0)) != 0u) {
    score += 4u;
  }
  if ((changed_gate_mask & (1u << 1)) != 0u) {
    score += 8u;
  }
  if ((changed_gate_mask & (1u << 2)) != 0u) {
    score += 8u;
  }
  if ((changed_gate_mask & (1u << 3)) != 0u) {
    score += 16u;
  }
  if ((changed_gate_mask & (1u << 4)) != 0u) {
    score += 12u;
  }
  return score;
}

int aegis_permission_center_submit_change_request(const aegis_sandbox_policy_t *before_policy,
                                                  const aegis_sandbox_policy_t *proposed_policy,
                                                  uint64_t now_epoch,
                                                  const char *requested_by,
                                                  const char *rationale,
                                                  uint64_t *request_id_out) {
  char reason[64];
  size_t idx;
  uint32_t added_caps;
  uint32_t changed_gates;
  if (before_policy == 0 || proposed_policy == 0 || request_id_out == 0) {
    return -1;
  }
  if (!aegis_sandbox_policy_validate(before_policy, reason, sizeof(reason)) ||
      !aegis_sandbox_policy_validate(proposed_policy, reason, sizeof(reason))) {
    return -1;
  }
  if (before_policy->process_id != proposed_policy->process_id) {
    return -1;
  }
  idx = g_permission_center_request_count % 256u;
  memset(&g_permission_center_requests[idx], 0, sizeof(g_permission_center_requests[idx]));
  g_permission_center_requests[idx].request_id = g_permission_center_next_request_id;
  g_permission_center_requests[idx].created_epoch = now_epoch;
  g_permission_center_requests[idx].process_id = proposed_policy->process_id;
  g_permission_center_requests[idx].status = AEGIS_PERMISSION_APPROVAL_PENDING;
  g_permission_center_requests[idx].before_policy = *before_policy;
  g_permission_center_requests[idx].proposed_policy = *proposed_policy;
  added_caps = proposed_policy->capabilities & (~before_policy->capabilities);
  changed_gates = permission_center_gate_mask(before_policy) ^ permission_center_gate_mask(proposed_policy);
  g_permission_center_requests[idx].risk_score =
      capability_risk_score(added_caps) + gate_risk_score(changed_gates);
  g_permission_center_requests[idx].requires_security_review =
      g_permission_center_requests[idx].risk_score >= 25u ? 1u : 0u;
  snprintf(g_permission_center_requests[idx].requested_by,
           sizeof(g_permission_center_requests[idx].requested_by),
           "%s",
           requested_by != 0 ? requested_by : "unknown");
  snprintf(g_permission_center_requests[idx].rationale,
           sizeof(g_permission_center_requests[idx].rationale),
           "%s",
           rationale != 0 ? rationale : "policy_change_request");
  *request_id_out = g_permission_center_next_request_id;
  g_permission_center_next_request_id += 1u;
  g_permission_center_request_count += 1u;
  return 0;
}

int aegis_permission_center_approve_change_request(uint64_t request_id,
                                                   uint64_t now_epoch,
                                                   const char *resolved_by,
                                                   const char *note,
                                                   aegis_sandbox_policy_t *applied_policy_out) {
  size_t idx;
  const char *actor = resolved_by != 0 ? resolved_by : "reviewer";
  if (applied_policy_out == 0 || !find_request_index_by_id(request_id, &idx)) {
    return -1;
  }
  if (g_permission_center_requests[idx].status != AEGIS_PERMISSION_APPROVAL_PENDING) {
    return -1;
  }
  if (g_permission_center_requests[idx].requires_security_review != 0u &&
      strncmp(actor, "security-", 9) != 0) {
    return -1;
  }
  g_permission_center_requests[idx].status = AEGIS_PERMISSION_APPROVAL_APPROVED;
  g_permission_center_requests[idx].resolved_epoch = now_epoch;
  snprintf(g_permission_center_requests[idx].resolved_by,
           sizeof(g_permission_center_requests[idx].resolved_by),
           "%s",
           actor);
  snprintf(g_permission_center_requests[idx].resolution_note,
           sizeof(g_permission_center_requests[idx].resolution_note),
           "%s",
           note != 0 ? note : "approved");
  *applied_policy_out = g_permission_center_requests[idx].proposed_policy;
  return 0;
}

int aegis_permission_center_reject_change_request(uint64_t request_id,
                                                  uint64_t now_epoch,
                                                  const char *resolved_by,
                                                  const char *note) {
  size_t idx;
  if (!find_request_index_by_id(request_id, &idx)) {
    return -1;
  }
  if (g_permission_center_requests[idx].status != AEGIS_PERMISSION_APPROVAL_PENDING) {
    return -1;
  }
  g_permission_center_requests[idx].status = AEGIS_PERMISSION_APPROVAL_REJECTED;
  g_permission_center_requests[idx].resolved_epoch = now_epoch;
  snprintf(g_permission_center_requests[idx].resolved_by,
           sizeof(g_permission_center_requests[idx].resolved_by),
           "%s",
           resolved_by != 0 ? resolved_by : "reviewer");
  snprintf(g_permission_center_requests[idx].resolution_note,
           sizeof(g_permission_center_requests[idx].resolution_note),
           "%s",
           note != 0 ? note : "rejected");
  return 0;
}

int aegis_permission_center_approval_export_json(char *output, size_t output_size) {
  size_t offset = 0u;
  size_t total =
      g_permission_center_request_count > 256u ? 256u : g_permission_center_request_count;
  size_t base =
      g_permission_center_request_count > 256u ? g_permission_center_request_count - 256u : 0u;
  size_t i;
  int written;
  if (output == 0 || output_size == 0u) {
    return -1;
  }
  written = snprintf(output,
                     output_size,
                     "{\"schema_version\":1,\"request_count\":%llu,\"pending_count\":%llu,"
                     "\"requests\":[",
                     (unsigned long long)total,
                     (unsigned long long)aegis_permission_center_approval_pending_count());
  if (written < 0 || (size_t)written >= output_size) {
    return -1;
  }
  offset = (size_t)written;
  for (i = 0; i < total; ++i) {
    size_t idx = (base + i) % 256u;
    const aegis_permission_change_request_t *req = &g_permission_center_requests[idx];
    written = snprintf(output + offset,
                       output_size - offset,
                       "%s{\"request_id\":%llu,\"process_id\":%u,\"status\":%u,"
                       "\"created_epoch\":%llu,\"resolved_epoch\":%llu,"
                       "\"requested_by\":\"%s\",\"resolved_by\":\"%s\",\"rationale\":\"%s\","
                       "\"resolution_note\":\"%s\",\"risk_score\":%u,"
                       "\"requires_security_review\":%u,\"before_revision\":%llu,"
                       "\"proposed_revision\":%llu}",
                       i == 0u ? "" : ",",
                       (unsigned long long)req->request_id,
                       req->process_id,
                       (unsigned int)req->status,
                       (unsigned long long)req->created_epoch,
                       (unsigned long long)req->resolved_epoch,
                       req->requested_by,
                       req->resolved_by,
                       req->rationale,
                       req->resolution_note,
                       req->risk_score,
                       (unsigned int)req->requires_security_review,
                       (unsigned long long)policy_revision(&req->before_policy),
                       (unsigned long long)policy_revision(&req->proposed_policy));
    if (written < 0 || (size_t)written >= (output_size - offset)) {
      return -1;
    }
    offset += (size_t)written;
  }
  written = snprintf(output + offset, output_size - offset, "]}");
  if (written < 0 || (size_t)written >= (output_size - offset)) {
    return -1;
  }
  offset += (size_t)written;
  return (int)offset;
}

int aegis_permission_center_approval_metrics_json(char *output, size_t output_size) {
  size_t i;
  size_t total =
      g_permission_center_request_count > 256u ? 256u : g_permission_center_request_count;
  size_t base =
      g_permission_center_request_count > 256u ? g_permission_center_request_count - 256u : 0u;
  uint64_t pending = 0u;
  uint64_t approved = 0u;
  uint64_t rejected = 0u;
  uint64_t security_review_required = 0u;
  uint64_t security_review_pending = 0u;
  uint64_t risk_score_sum = 0u;
  int written;
  if (output == 0 || output_size == 0u) {
    return -1;
  }
  for (i = 0; i < total; ++i) {
    size_t idx = (base + i) % 256u;
    const aegis_permission_change_request_t *req = &g_permission_center_requests[idx];
    risk_score_sum += req->risk_score;
    if (req->status == AEGIS_PERMISSION_APPROVAL_PENDING) {
      pending += 1u;
    } else if (req->status == AEGIS_PERMISSION_APPROVAL_APPROVED) {
      approved += 1u;
    } else if (req->status == AEGIS_PERMISSION_APPROVAL_REJECTED) {
      rejected += 1u;
    }
    if (req->requires_security_review != 0u) {
      security_review_required += 1u;
      if (req->status == AEGIS_PERMISSION_APPROVAL_PENDING) {
        security_review_pending += 1u;
      }
    }
  }
  written = snprintf(output,
                     output_size,
                     "{\"schema_version\":1,\"request_count\":%llu,\"pending_count\":%llu,"
                     "\"approved_count\":%llu,\"rejected_count\":%llu,"
                     "\"security_review_required_count\":%llu,"
                     "\"security_review_pending_count\":%llu,\"risk_score_sum\":%llu}",
                     (unsigned long long)total,
                     (unsigned long long)pending,
                     (unsigned long long)approved,
                     (unsigned long long)rejected,
                     (unsigned long long)security_review_required,
                     (unsigned long long)security_review_pending,
                     (unsigned long long)risk_score_sum);
  if (written < 0 || (size_t)written >= output_size) {
    return -1;
  }
  return written;
}
