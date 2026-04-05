#include "sandbox_policy.h"

#include <stdio.h>
#include <string.h>

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
  unsigned int process_id = 0;
  unsigned int capabilities = 0;
  unsigned int allow_fs_read = 0;
  unsigned int allow_fs_write = 0;
  unsigned int allow_net_client = 0;
  unsigned int allow_net_server = 0;
  unsigned int schema_version = 0;
  unsigned long long policy_rev = 0;
  unsigned int allow_device_io = 0;
  int matched = 0;
  if (reason != 0 && reason_size > 0) {
    reason[0] = '\0';
  }
  if (input == 0 || policy == 0) {
    write_reason(reason, reason_size, "input or policy is null");
    return -1;
  }
  matched = sscanf(
      input,
      "{\"process_id\":%u,\"capabilities\":%u,\"allow_fs_read\":%u,"
      "\"allow_fs_write\":%u,\"allow_net_client\":%u,\"allow_net_server\":%u,"
      "\"schema_version\":%u,\"policy_revision\":%llu,\"allow_device_io\":%u}",
      &process_id,
      &capabilities,
      &allow_fs_read,
      &allow_fs_write,
      &allow_net_client,
      &allow_net_server,
      &schema_version,
      &policy_rev,
      &allow_device_io);
  if (matched != 9) {
    matched = sscanf(
        input,
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
      write_reason(reason, reason_size, "invalid sandbox policy JSON format");
      return -1;
    }
    schema_version = AEGIS_SANDBOX_POLICY_SCHEMA_VERSION;
    policy_rev = 1u;
  }
  policy->process_id = process_id;
  policy->capabilities = capabilities;
  policy->schema_version = schema_version;
  policy->policy_revision = (uint64_t)policy_rev;
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
      (caps & AEGIS_CAP_FS_READ) != 0u ? "allow" : "deny",
      (caps & AEGIS_CAP_FS_WRITE) != 0u ? "allow" : "deny",
      (caps & AEGIS_CAP_NET_CLIENT) != 0u ? "allow" : "deny",
      (caps & AEGIS_CAP_NET_SERVER) != 0u ? "allow" : "deny",
      (caps & AEGIS_CAP_DEVICE_IO) != 0u ? "allow" : "deny");
  if (written < 0 || (size_t)written >= output_size) {
    return -1;
  }
  return 0;
}
