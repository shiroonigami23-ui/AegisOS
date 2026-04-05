#include <stdio.h>
#include <string.h>

#include "sandbox_policy.h"

static int test_valid_policy(void) {
  aegis_sandbox_policy_t policy = {
      10u, AEGIS_CAP_FS_READ | AEGIS_CAP_NET_CLIENT, 1u, 0u, 1u, 0u, 0u};
  char reason[64];

  if (!aegis_sandbox_policy_validate(&policy, reason, sizeof(reason))) {
    fprintf(stderr, "expected valid policy, got: %s\n", reason);
    return 1;
  }
  if (!aegis_sandbox_policy_allows(&policy, AEGIS_CAP_FS_READ)) {
    fprintf(stderr, "expected FS_READ to be allowed\n");
    return 1;
  }
  if (aegis_sandbox_policy_allows(&policy, AEGIS_CAP_FS_WRITE)) {
    fprintf(stderr, "expected FS_WRITE to be denied\n");
    return 1;
  }
  return 0;
}

static int test_invalid_policy(void) {
  aegis_sandbox_policy_t bad_policy = {0u, AEGIS_CAP_NET_SERVER, 0u, 0u, 0u, 1u, 0u};
  char reason[64];

  if (aegis_sandbox_policy_validate(&bad_policy, reason, sizeof(reason))) {
    fprintf(stderr, "expected invalid policy to fail\n");
    return 1;
  }
  if (strcmp(reason, "process_id must be non-zero") != 0) {
    fprintf(stderr, "unexpected reason: %s\n", reason);
    return 1;
  }
  return 0;
}

static int test_policy_json_roundtrip(void) {
  aegis_sandbox_policy_t policy = {
      42u, AEGIS_CAP_FS_READ | AEGIS_CAP_NET_CLIENT, 1u, 0u, 1u, 0u, 0u};
  aegis_sandbox_policy_t parsed = {0u, 0u, 0u, 0u, 0u, 0u, 0u};
  char json[256];
  char reason[64];

  if (aegis_sandbox_policy_serialize_json(&policy, json, sizeof(json)) != 0) {
    fprintf(stderr, "expected serialize to succeed\n");
    return 1;
  }
  if (aegis_sandbox_policy_deserialize_json(json, &parsed, reason, sizeof(reason)) != 0) {
    fprintf(stderr, "expected deserialize to succeed: %s\n", reason);
    return 1;
  }
  if (parsed.process_id != policy.process_id || parsed.capabilities != policy.capabilities ||
      parsed.allow_fs_read != policy.allow_fs_read ||
      parsed.allow_fs_write != policy.allow_fs_write ||
      parsed.allow_net_client != policy.allow_net_client ||
      parsed.allow_net_server != policy.allow_net_server ||
      parsed.allow_device_io != policy.allow_device_io) {
    fprintf(stderr, "roundtrip mismatch\n");
    return 1;
  }
  return 0;
}

static int test_policy_json_invalid_payload(void) {
  const char *bad = "{\"process_id\":0,\"capabilities\":8}";
  aegis_sandbox_policy_t parsed = {0u, 0u, 0u, 0u, 0u, 0u, 0u};
  char reason[64];
  if (aegis_sandbox_policy_deserialize_json(bad, &parsed, reason, sizeof(reason)) == 0) {
    fprintf(stderr, "expected invalid payload to fail\n");
    return 1;
  }
  return 0;
}

int main(void) {
  if (test_valid_policy() != 0) {
    return 1;
  }
  if (test_invalid_policy() != 0) {
    return 1;
  }
  if (test_policy_json_roundtrip() != 0) {
    return 1;
  }
  if (test_policy_json_invalid_payload() != 0) {
    return 1;
  }
  puts("sandbox policy tests passed");
  return 0;
}
