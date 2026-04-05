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
  if (strstr(json, "\"schema_version\":1") == 0 || strstr(json, "\"policy_revision\":1") == 0) {
    fprintf(stderr, "version fields missing from JSON\n");
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

static int test_policy_schema_version_guard(void) {
  aegis_sandbox_policy_t bad_schema = {
      99u, AEGIS_CAP_FS_READ, 1u, 0u, 0u, 0u, 0u, 99u, 1u};
  char reason[64];
  if (aegis_sandbox_policy_validate(&bad_schema, reason, sizeof(reason))) {
    fprintf(stderr, "expected bad schema to fail\n");
    return 1;
  }
  if (strcmp(reason, "unsupported sandbox policy schema_version") != 0) {
    fprintf(stderr, "unexpected schema reason: %s\n", reason);
    return 1;
  }
  return 0;
}

static int test_policy_legacy_migration_adapter(void) {
  const char *legacy =
      "{\"process_id\":123,\"capabilities\":5,\"allow_fs_read\":1,"
      "\"allow_fs_write\":0,\"allow_net_client\":1,\"allow_net_server\":0,"
      "\"allow_device_io\":0}";
  char migrated_json[512];
  char reason[64];
  aegis_sandbox_policy_migration_report_t report;
  aegis_sandbox_policy_t parsed = {0u};

  if (aegis_sandbox_policy_migrate_legacy_json(legacy, migrated_json, sizeof(migrated_json), &report,
                                               reason, sizeof(reason)) != 0) {
    fprintf(stderr, "expected migration to succeed: %s\n", reason);
    return 1;
  }
  if (report.migrated == 0u || report.to_schema_version != AEGIS_SANDBOX_POLICY_SCHEMA_VERSION) {
    fprintf(stderr, "unexpected migration report\n");
    return 1;
  }
  if (strstr(migrated_json, "\"schema_version\":1") == 0 ||
      strstr(migrated_json, "\"policy_revision\":1") == 0) {
    fprintf(stderr, "migrated json missing version metadata\n");
    return 1;
  }
  if (aegis_sandbox_policy_deserialize_json(migrated_json, &parsed, reason, sizeof(reason)) != 0) {
    fprintf(stderr, "failed to parse migrated json: %s\n", reason);
    return 1;
  }
  if (parsed.process_id != 123u || parsed.schema_version != AEGIS_SANDBOX_POLICY_SCHEMA_VERSION) {
    fprintf(stderr, "parsed migrated policy mismatch\n");
    return 1;
  }
  return 0;
}

static int test_permission_center_policy_summary_endpoint(void) {
  aegis_sandbox_policy_t policy = {
      210u,
      AEGIS_CAP_FS_READ | AEGIS_CAP_NET_CLIENT | AEGIS_CAP_DEVICE_IO,
      1u,
      0u,
      1u,
      0u,
      1u,
      AEGIS_SANDBOX_POLICY_SCHEMA_VERSION,
      9u};
  char json[768];
  if (aegis_permission_center_policy_summary_json(&policy, json, sizeof(json)) != 0) {
    fprintf(stderr, "expected permission center summary endpoint to succeed\n");
    return 1;
  }
  if (strstr(json, "\"schema_version\":1") == 0 ||
      strstr(json, "\"process_id\":210") == 0 ||
      strstr(json, "\"policy_revision\":9") == 0 ||
      strstr(json, "\"capability_mask\":21") == 0) {
    fprintf(stderr, "summary endpoint missing version/process metadata: %s\n", json);
    return 1;
  }
  if (strstr(json, "\"fs_read\":1") == 0 ||
      strstr(json, "\"fs_write\":0") == 0 ||
      strstr(json, "\"net_client\":1") == 0 ||
      strstr(json, "\"net_server\":0") == 0 ||
      strstr(json, "\"device_io\":1") == 0) {
    fprintf(stderr, "summary endpoint missing capability visibility fields: %s\n", json);
    return 1;
  }
  if (strstr(json, "\"fs.read\":\"allow\"") == 0 ||
      strstr(json, "\"fs.write\":\"deny\"") == 0 ||
      strstr(json, "\"net.connect\":\"allow\"") == 0 ||
      strstr(json, "\"net.listen\":\"deny\"") == 0 ||
      strstr(json, "\"device.io\":\"allow\"") == 0) {
    fprintf(stderr, "summary endpoint missing action allow/deny mapping: %s\n", json);
    return 1;
  }
  return 0;
}

static int test_permission_center_policy_summary_rejects_invalid_policy(void) {
  aegis_sandbox_policy_t invalid = {
      0u,
      AEGIS_CAP_FS_READ,
      1u,
      0u,
      0u,
      0u,
      0u,
      AEGIS_SANDBOX_POLICY_SCHEMA_VERSION,
      1u};
  char json[128];
  if (aegis_permission_center_policy_summary_json(&invalid, json, sizeof(json)) == 0) {
    fprintf(stderr, "summary endpoint should fail invalid policy\n");
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
  if (test_policy_schema_version_guard() != 0) {
    return 1;
  }
  if (test_policy_legacy_migration_adapter() != 0) {
    return 1;
  }
  if (test_permission_center_policy_summary_endpoint() != 0) {
    return 1;
  }
  if (test_permission_center_policy_summary_rejects_invalid_policy() != 0) {
    return 1;
  }
  puts("sandbox policy tests passed");
  return 0;
}
