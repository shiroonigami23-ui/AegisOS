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

static int test_policy_json_field_order_tolerant_parse(void) {
  const char *payload =
      "{\"allow_device_io\":0,\"policy_revision\":7,\"allow_net_server\":0,"
      "\"allow_fs_write\":0,\"schema_version\":1,\"allow_fs_read\":1,"
      "\"process_id\":77,\"capabilities\":5,\"allow_net_client\":1}";
  aegis_sandbox_policy_t parsed = {0u};
  char reason[64];
  if (aegis_sandbox_policy_deserialize_json(payload, &parsed, reason, sizeof(reason)) != 0) {
    fprintf(stderr, "expected field-order tolerant parse to pass: %s\n", reason);
    return 1;
  }
  if (parsed.process_id != 77u || parsed.policy_revision != 7u || parsed.allow_net_client != 1u) {
    fprintf(stderr, "field-order tolerant parse produced unexpected values\n");
    return 1;
  }
  return 0;
}

static int test_policy_json_non_numeric_field_rejected(void) {
  const char *payload =
      "{\"process_id\":77,\"capabilities\":\"bad\",\"allow_fs_read\":1,"
      "\"allow_fs_write\":0,\"allow_net_client\":1,\"allow_net_server\":0,"
      "\"schema_version\":1,\"policy_revision\":1,\"allow_device_io\":0}";
  aegis_sandbox_policy_t parsed = {0u};
  char reason[64];
  if (aegis_sandbox_policy_deserialize_json(payload, &parsed, reason, sizeof(reason)) == 0) {
    fprintf(stderr, "expected non-numeric capabilities to fail parse\n");
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

static int test_permission_center_summary_respects_policy_gates(void) {
  aegis_sandbox_policy_t policy = {
      211u,
      AEGIS_CAP_FS_READ | AEGIS_CAP_FS_WRITE,
      1u,
      0u,
      0u,
      0u,
      0u,
      AEGIS_SANDBOX_POLICY_SCHEMA_VERSION,
      2u};
  char json[512];
  if (aegis_permission_center_policy_summary_json(&policy, json, sizeof(json)) != 0) {
    fprintf(stderr, "expected summary endpoint to serialize gated policy\n");
    return 1;
  }
  if (strstr(json, "\"fs_write\":1") == 0) {
    fprintf(stderr, "expected capability visibility to show fs_write capability bit: %s\n", json);
    return 1;
  }
  if (strstr(json, "\"fs.write\":\"deny\"") == 0) {
    fprintf(stderr, "expected action map to deny fs.write when policy gate is off: %s\n", json);
    return 1;
  }
  return 0;
}

static int test_permission_center_policy_diff_endpoint(void) {
  aegis_sandbox_policy_t before = {
      500u,
      AEGIS_CAP_FS_READ | AEGIS_CAP_NET_CLIENT,
      1u,
      0u,
      1u,
      0u,
      0u,
      AEGIS_SANDBOX_POLICY_SCHEMA_VERSION,
      3u};
  aegis_sandbox_policy_t after = {
      500u,
      AEGIS_CAP_FS_READ | AEGIS_CAP_FS_WRITE | AEGIS_CAP_NET_CLIENT,
      1u,
      1u,
      1u,
      0u,
      0u,
      AEGIS_SANDBOX_POLICY_SCHEMA_VERSION,
      4u};
  char json[512];
  if (aegis_permission_center_policy_diff_json(&before, &after, json, sizeof(json)) <= 0) {
    fprintf(stderr, "permission center diff endpoint failed\n");
    return 1;
  }
  if (strstr(json, "\"process_id\":500") == 0 ||
      strstr(json, "\"before_revision\":3") == 0 ||
      strstr(json, "\"after_revision\":4") == 0 ||
      strstr(json, "\"added_capability_mask\":2") == 0 ||
      strstr(json, "\"changed_gate_mask\":2") == 0) {
    fprintf(stderr, "permission center diff json missing expected fields: %s\n", json);
    return 1;
  }
  return 0;
}

static int test_permission_center_audit_export_endpoints(void) {
  aegis_sandbox_policy_t before = {
      777u,
      AEGIS_CAP_FS_READ,
      1u,
      0u,
      0u,
      0u,
      0u,
      AEGIS_SANDBOX_POLICY_SCHEMA_VERSION,
      1u};
  aegis_sandbox_policy_t after = {
      777u,
      AEGIS_CAP_FS_READ | AEGIS_CAP_DEVICE_IO,
      1u,
      0u,
      0u,
      0u,
      1u,
      AEGIS_SANDBOX_POLICY_SCHEMA_VERSION,
      2u};
  char json[1024];
  char csv[1024];
  aegis_permission_center_audit_reset();
  if (aegis_permission_center_record_policy_change(&before,
                                                   &after,
                                                   12345u,
                                                   "policyd",
                                                   "grant_device_io") != 0) {
    fprintf(stderr, "permission center audit record failed\n");
    return 1;
  }
  if (aegis_permission_center_audit_count() != 1u) {
    fprintf(stderr, "permission center audit count mismatch\n");
    return 1;
  }
  if (aegis_permission_center_audit_export_json(json, sizeof(json)) <= 0) {
    fprintf(stderr, "permission center audit json export failed\n");
    return 1;
  }
  if (strstr(json, "\"process_id\":777") == 0 ||
      strstr(json, "\"actor\":\"policyd\"") == 0 ||
      strstr(json, "\"reason\":\"grant_device_io\"") == 0 ||
      strstr(json, "\"added_capability_mask\":16") == 0) {
    fprintf(stderr, "permission center audit json missing expected fields: %s\n", json);
    return 1;
  }
  if (aegis_permission_center_audit_export_csv(csv, sizeof(csv)) <= 0) {
    fprintf(stderr, "permission center audit csv export failed\n");
    return 1;
  }
  if (strstr(csv, "timestamp_epoch,process_id,before_revision,after_revision") == 0 ||
      strstr(csv, "777") == 0 ||
      strstr(csv, "policyd") == 0) {
    fprintf(stderr, "permission center audit csv missing expected fields: %s\n", csv);
    return 1;
  }
  return 0;
}

static int test_permission_center_change_approval_flow(void) {
  aegis_sandbox_policy_t before = {
      880u,
      AEGIS_CAP_FS_READ,
      1u,
      0u,
      0u,
      0u,
      0u,
      AEGIS_SANDBOX_POLICY_SCHEMA_VERSION,
      4u};
  aegis_sandbox_policy_t proposed = {
      880u,
      AEGIS_CAP_FS_READ | AEGIS_CAP_NET_CLIENT | AEGIS_CAP_DEVICE_IO,
      1u,
      0u,
      1u,
      0u,
      1u,
      AEGIS_SANDBOX_POLICY_SCHEMA_VERSION,
      5u};
  aegis_sandbox_policy_t applied;
  uint64_t req_approve = 0u;
  uint64_t req_reject = 0u;
  char json[2048];
  char metrics[512];
  char tiny[32];
  memset(&applied, 0, sizeof(applied));

  aegis_permission_center_approval_reset();
  if (aegis_permission_center_submit_change_request(&before,
                                                    &proposed,
                                                    200u,
                                                    "settings-ui",
                                                    "user_enabled_network",
                                                    &req_approve) != 0 ||
      req_approve == 0u) {
    fprintf(stderr, "approval flow submit approve-request failed\n");
    return 1;
  }
  if (aegis_permission_center_submit_change_request(&before,
                                                    &proposed,
                                                    201u,
                                                    "settings-ui",
                                                    "second_request_for_reject_path",
                                                    &req_reject) != 0 ||
      req_reject == 0u) {
    fprintf(stderr, "approval flow submit reject-request failed\n");
    return 1;
  }
  if (aegis_permission_center_approval_count() != 2u ||
      aegis_permission_center_approval_pending_count() != 2u) {
    fprintf(stderr, "approval flow expected 2 pending requests\n");
    return 1;
  }
  if (aegis_permission_center_approve_change_request(req_approve,
                                                     210u,
                                                     "policy-admin",
                                                     "approved_after_review",
                                                     &applied) == 0) {
    fprintf(stderr, "approval flow should reject non-security approver for high-risk request\n");
    return 1;
  }
  if (aegis_permission_center_approve_change_request(req_approve,
                                                     210u,
                                                     "security-admin",
                                                     "approved_after_security_review",
                                                     &applied) != 0) {
    fprintf(stderr, "approval flow approve failed\n");
    return 1;
  }
  if (applied.process_id != proposed.process_id ||
      applied.policy_revision != proposed.policy_revision ||
      applied.allow_net_client != 1u) {
    fprintf(stderr, "approval flow applied policy mismatch\n");
    return 1;
  }
  if (aegis_permission_center_reject_change_request(req_reject,
                                                    211u,
                                                    "policy-admin",
                                                    "risk_not_accepted") != 0) {
    fprintf(stderr, "approval flow reject failed\n");
    return 1;
  }
  if (aegis_permission_center_approval_pending_count() != 0u) {
    fprintf(stderr, "approval flow expected no pending requests after resolve\n");
    return 1;
  }
  if (aegis_permission_center_approval_export_json(json, sizeof(json)) <= 0 ||
      strstr(json, "\"schema_version\":1") == 0 ||
      strstr(json, "\"request_count\":2") == 0 ||
      strstr(json, "\"pending_count\":0") == 0 ||
      strstr(json, "\"status\":2") == 0 ||
      strstr(json, "\"status\":3") == 0 ||
      strstr(json, "\"risk_score\":55") == 0 ||
      strstr(json, "\"requires_security_review\":1") == 0 ||
      strstr(json, "\"requested_by\":\"settings-ui\"") == 0 ||
      strstr(json, "\"resolved_by\":\"security-admin\"") == 0) {
    fprintf(stderr, "approval flow json missing expected fields: %s\n", json);
    return 1;
  }
  if (aegis_permission_center_approval_metrics_json(metrics, sizeof(metrics)) <= 0 ||
      strstr(metrics, "\"schema_version\":1") == 0 ||
      strstr(metrics, "\"request_count\":2") == 0 ||
      strstr(metrics, "\"approved_count\":1") == 0 ||
      strstr(metrics, "\"rejected_count\":1") == 0 ||
      strstr(metrics, "\"security_review_required_count\":2") == 0) {
    fprintf(stderr, "approval flow metrics missing expected fields: %s\n", metrics);
    return 1;
  }
  if (aegis_permission_center_approval_export_json(tiny, sizeof(tiny)) >= 0) {
    fprintf(stderr, "approval flow expected tiny json buffer failure\n");
    return 1;
  }
  if (aegis_permission_center_approve_change_request(req_approve,
                                                     212u,
                                                     "policy-admin",
                                                     "duplicate_approve",
                                                     &applied) == 0) {
    fprintf(stderr, "approval flow duplicate approve should fail\n");
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
  if (test_policy_json_field_order_tolerant_parse() != 0) {
    return 1;
  }
  if (test_policy_json_non_numeric_field_rejected() != 0) {
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
  if (test_permission_center_summary_respects_policy_gates() != 0) {
    return 1;
  }
  if (test_permission_center_policy_diff_endpoint() != 0) {
    return 1;
  }
  if (test_permission_center_audit_export_endpoints() != 0) {
    return 1;
  }
  if (test_permission_center_change_approval_flow() != 0) {
    return 1;
  }
  puts("sandbox policy tests passed");
  return 0;
}
