#include "sandbox_policy.h"

#include <stdio.h>
#include <string.h>

static void write_reason(char *reason, size_t reason_size, const char *message) {
  if (reason == 0 || reason_size == 0 || message == 0) {
    return;
  }
  snprintf(reason, reason_size, "%s", message);
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
      "\"allow_device_io\":%u}",
      policy->process_id,
      policy->capabilities,
      (unsigned int)policy->allow_fs_read,
      (unsigned int)policy->allow_fs_write,
      (unsigned int)policy->allow_net_client,
      (unsigned int)policy->allow_net_server,
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
  policy->process_id = process_id;
  policy->capabilities = capabilities;
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
