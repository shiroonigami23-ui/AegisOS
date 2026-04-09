#include <stdio.h>
#include <string.h>

#include "capability.h"

static int test_capability_validate(void) {
  aegis_capability_token_t token = {42u, AEGIS_CAP_FS_READ | AEGIS_CAP_NET_CLIENT, 0u, 0u, 0u};
  aegis_capability_token_t invalid_pid = {0u, AEGIS_CAP_FS_READ, 0u, 0u, 0u};

  if (!aegis_capability_validate(&token, AEGIS_CAP_FS_READ)) {
    fprintf(stderr, "expected read capability to pass\n");
    return 1;
  }
  if (aegis_capability_validate(&token, AEGIS_CAP_FS_WRITE)) {
    fprintf(stderr, "expected write capability to fail\n");
    return 1;
  }
  if (aegis_capability_validate(&invalid_pid, AEGIS_CAP_FS_READ)) {
    fprintf(stderr, "expected invalid process id to fail\n");
    return 1;
  }
  if (aegis_capability_validate(0, AEGIS_CAP_FS_READ)) {
    fprintf(stderr, "expected null token to fail\n");
    return 1;
  }
  return 0;
}

static int test_capability_lifecycle(void) {
  aegis_capability_store_t store;
  aegis_capability_store_init(&store);

  if (aegis_capability_issue(&store, 77u, AEGIS_CAP_FS_READ) != 0) {
    fprintf(stderr, "expected issue to pass\n");
    return 1;
  }
  if (!aegis_capability_is_allowed(&store, 77u, AEGIS_CAP_FS_READ)) {
    fprintf(stderr, "expected process 77 to have read access\n");
    return 1;
  }
  if (aegis_capability_is_allowed(&store, 77u, AEGIS_CAP_FS_WRITE)) {
    fprintf(stderr, "expected process 77 write access to fail\n");
    return 1;
  }
  if (aegis_capability_issue(&store, 77u, AEGIS_CAP_FS_READ | AEGIS_CAP_FS_WRITE) != 0) {
    fprintf(stderr, "expected permission upgrade to pass\n");
    return 1;
  }
  if (!aegis_capability_is_allowed(&store, 77u, AEGIS_CAP_FS_WRITE)) {
    fprintf(stderr, "expected process 77 write access after upgrade\n");
    return 1;
  }
  if (aegis_capability_revoke(&store, 77u) != 0) {
    fprintf(stderr, "expected revoke to pass\n");
    return 1;
  }
  if (aegis_capability_is_allowed(&store, 77u, AEGIS_CAP_FS_READ)) {
    fprintf(stderr, "expected revoked process to fail read access\n");
    return 1;
  }
  return 0;
}

static int test_capability_ttl_and_rotation(void) {
  aegis_capability_store_t store;
  aegis_capability_store_init(&store);

  if (aegis_capability_issue_with_ttl(&store, 88u, AEGIS_CAP_NET_CLIENT, 1000u, 30u) != 0) {
    fprintf(stderr, "expected ttl issue to pass\n");
    return 1;
  }
  if (!aegis_capability_is_allowed_at(&store, 88u, AEGIS_CAP_NET_CLIENT, 1020u)) {
    fprintf(stderr, "expected token to be valid before expiry\n");
    return 1;
  }
  if (aegis_capability_is_allowed_at(&store, 88u, AEGIS_CAP_NET_CLIENT, 1030u)) {
    fprintf(stderr, "expected token to expire at ttl boundary\n");
    return 1;
  }
  if (aegis_capability_rotate(&store, 88u, AEGIS_CAP_NET_CLIENT | AEGIS_CAP_NET_SERVER, 2000u, 20u) != 0) {
    fprintf(stderr, "expected rotate to pass\n");
    return 1;
  }
  if (!aegis_capability_is_allowed_at(&store, 88u, AEGIS_CAP_NET_SERVER, 2010u)) {
    fprintf(stderr, "expected rotated permissions to apply\n");
    return 1;
  }
  if (aegis_capability_is_allowed_at(&store, 88u, AEGIS_CAP_NET_SERVER, 2021u)) {
    fprintf(stderr, "expected rotated token to expire\n");
    return 1;
  }
  return 0;
}

static int test_rotation_metadata_audit(void) {
  aegis_capability_store_t store;
  aegis_capability_audit_event_t event;
  size_t n = 0;
  aegis_capability_store_init(&store);
  aegis_capability_audit_reset();
  aegis_actor_registry_reset();

  if (aegis_capability_issue_with_ttl(&store, 120u, AEGIS_CAP_FS_READ, 100u, 20u) != 0) {
    fprintf(stderr, "rotation metadata issue failed\n");
    return 1;
  }
  if (aegis_actor_registry_register(9001u, AEGIS_ACTOR_AUTOMATION, "automation") != 0) {
    fprintf(stderr, "rotation metadata actor registration failed\n");
    return 1;
  }
  if (aegis_capability_rotate_with_metadata(&store,
                                            120u,
                                            AEGIS_CAP_FS_READ | AEGIS_CAP_FS_WRITE,
                                            110u,
                                            20u,
                                            9001u,
                                            "incident_response") != 0) {
    fprintf(stderr, "rotation metadata rotate failed\n");
    return 1;
  }
  n = aegis_capability_audit_count();
  if (n < 2u) {
    fprintf(stderr, "expected rotation metadata audit entries\n");
    return 1;
  }
  if (aegis_capability_audit_get(n - 1u, &event) != 0) {
    fprintf(stderr, "failed to read metadata event\n");
    return 1;
  }
  if (event.event_type != AEGIS_CAP_AUDIT_ROTATE) {
    fprintf(stderr, "expected rotate event type\n");
    return 1;
  }
  if (event.actor_id != 9001u) {
    fprintf(stderr, "expected actor metadata 9001\n");
    return 1;
  }
  if (event.actor_source != AEGIS_ACTOR_AUTOMATION) {
    fprintf(stderr, "expected actor source automation\n");
    return 1;
  }
  if (strcmp(event.actor_label, "automation") != 0) {
    fprintf(stderr, "expected actor label automation\n");
    return 1;
  }
  if (strcmp(event.reason, "incident_response") != 0) {
    fprintf(stderr, "expected reason metadata incident_response\n");
    return 1;
  }
  return 0;
}

static int test_rotation_identity_validation(void) {
  aegis_capability_store_t store;
  aegis_capability_audit_event_t event;
  size_t n = 0;
  aegis_capability_store_init(&store);
  aegis_capability_audit_reset();
  aegis_actor_registry_reset();
  if (aegis_capability_issue_with_ttl(&store, 121u, AEGIS_CAP_FS_READ, 200u, 20u) != 0) {
    fprintf(stderr, "identity validation issue failed\n");
    return 1;
  }
  if (aegis_actor_registry_register(1001u, AEGIS_ACTOR_USER, "alice_admin") != 0) {
    fprintf(stderr, "identity actor registration failed\n");
    return 1;
  }
  if (aegis_capability_rotate_with_identity(&store,
                                            121u,
                                            AEGIS_CAP_FS_READ | AEGIS_CAP_FS_WRITE,
                                            205u,
                                            20u,
                                            1001u,
                                            AEGIS_ACTOR_USER,
                                            "alice_admin",
                                            "manual_grant") != 0) {
    fprintf(stderr, "expected valid actor identity rotate to pass\n");
    return 1;
  }
  n = aegis_capability_audit_count();
  if (aegis_capability_audit_get(n - 1u, &event) != 0) {
    fprintf(stderr, "failed to read identity rotate event\n");
    return 1;
  }
  if (event.actor_source != AEGIS_ACTOR_USER || strcmp(event.actor_label, "alice_admin") != 0) {
    fprintf(stderr, "identity fields not persisted correctly\n");
    return 1;
  }
  if (aegis_capability_rotate_with_identity(&store,
                                            121u,
                                            AEGIS_CAP_FS_READ,
                                            210u,
                                            20u,
                                            0u,
                                            AEGIS_ACTOR_USER,
                                            "bob",
                                            "invalid_identity") == 0) {
    fprintf(stderr, "expected invalid identity to fail\n");
    return 1;
  }
  return 0;
}

static int test_actor_registry_and_revocation_hooks(void) {
  aegis_capability_store_t store;
  aegis_capability_audit_event_t event;
  aegis_actor_registry_entry_t actor;
  size_t n = 0;
  aegis_capability_store_init(&store);
  aegis_capability_audit_reset();
  aegis_actor_registry_reset();

  if (aegis_actor_registry_register(3001u, AEGIS_ACTOR_SERVICE, "policyd") != 0) {
    fprintf(stderr, "actor registry register failed\n");
    return 1;
  }
  if (aegis_actor_registry_lookup(3001u, AEGIS_ACTOR_SERVICE, &actor) != 0) {
    fprintf(stderr, "actor registry lookup failed\n");
    return 1;
  }
  if (actor.active == 0 || actor.revoked != 0 || strcmp(actor.actor_label, "policyd") != 0) {
    fprintf(stderr, "actor registry lookup returned invalid entry\n");
    return 1;
  }
  if (aegis_capability_issue_with_ttl(&store, 130u, AEGIS_CAP_FS_READ, 300u, 20u) != 0) {
    fprintf(stderr, "registry hook issue failed\n");
    return 1;
  }
  if (aegis_capability_rotate_with_identity(&store,
                                            130u,
                                            AEGIS_CAP_FS_READ | AEGIS_CAP_FS_WRITE,
                                            301u,
                                            20u,
                                            3001u,
                                            AEGIS_ACTOR_SERVICE,
                                            "policyd",
                                            "registry_rotate") != 0) {
    fprintf(stderr, "expected rotate with active actor to pass\n");
    return 1;
  }
  if (aegis_actor_registry_revoke(3001u, AEGIS_ACTOR_SERVICE, 302u, "retired") != 0) {
    fprintf(stderr, "actor registry revoke failed\n");
    return 1;
  }
  if (aegis_capability_rotate_with_identity(&store,
                                            130u,
                                            AEGIS_CAP_FS_READ,
                                            303u,
                                            20u,
                                            3001u,
                                            AEGIS_ACTOR_SERVICE,
                                            "policyd",
                                            "should_fail_after_revoke") == 0) {
    fprintf(stderr, "expected rotate with revoked actor to fail\n");
    return 1;
  }
  if (aegis_capability_revoke_with_identity(&store,
                                            130u,
                                            304u,
                                            3001u,
                                            AEGIS_ACTOR_SERVICE,
                                            "policyd",
                                            "should_fail_revoke_actor") == 0) {
    fprintf(stderr, "expected token revoke with revoked actor to fail\n");
    return 1;
  }
  if (aegis_actor_registry_register(3001u, AEGIS_ACTOR_SERVICE, "policyd") != 0) {
    fprintf(stderr, "actor registry re-register failed\n");
    return 1;
  }
  if (aegis_capability_revoke_with_identity(&store,
                                            130u,
                                            305u,
                                            3001u,
                                            AEGIS_ACTOR_SERVICE,
                                            "policyd",
                                            "deprovision") != 0) {
    fprintf(stderr, "expected token revoke with active actor to pass\n");
    return 1;
  }
  n = aegis_capability_audit_count();
  if (n == 0u || aegis_capability_audit_get(n - 1u, &event) != 0) {
    fprintf(stderr, "failed to read revoke audit event\n");
    return 1;
  }
  if (event.event_type != AEGIS_CAP_AUDIT_REVOKE ||
      event.actor_id != 3001u ||
      event.actor_source != AEGIS_ACTOR_SERVICE ||
      strcmp(event.actor_label, "policyd") != 0 ||
      strcmp(event.reason, "deprovision") != 0) {
    fprintf(stderr, "revoke audit event missing actor hook fields\n");
    return 1;
  }
  return 0;
}

static int test_capability_audit_pipeline(void) {
  aegis_capability_store_t store;
  aegis_capability_audit_event_t event;
  aegis_capability_store_init(&store);
  aegis_capability_audit_reset();

  if (aegis_capability_issue_with_ttl(&store, 99u, AEGIS_CAP_FS_READ, 10u, 5u) != 0) {
    fprintf(stderr, "audit test issue failed\n");
    return 1;
  }
  (void)aegis_capability_is_allowed_at(&store, 99u, AEGIS_CAP_FS_READ, 12u);
  (void)aegis_capability_is_allowed_at(&store, 99u, AEGIS_CAP_FS_WRITE, 12u);
  if (aegis_capability_revoke(&store, 99u) != 0) {
    fprintf(stderr, "audit test revoke failed\n");
    return 1;
  }
  if (aegis_capability_audit_count() < 4u) {
    fprintf(stderr, "expected at least 4 audit events\n");
    return 1;
  }
  if (aegis_capability_audit_get(aegis_capability_audit_count() - 1u, &event) != 0) {
    fprintf(stderr, "failed to read latest audit event\n");
    return 1;
  }
  if (event.event_type != AEGIS_CAP_AUDIT_REVOKE) {
    fprintf(stderr, "expected latest event to be revoke\n");
    return 1;
  }
  return 0;
}

static int test_capability_audit_export_api(void) {
  aegis_capability_store_t store;
  char json[4096];
  char csv[4096];
  aegis_capability_store_init(&store);
  aegis_capability_audit_reset();

  if (aegis_capability_issue_with_ttl(&store, 500u, AEGIS_CAP_FS_READ, 42u, 15u) != 0) {
    fprintf(stderr, "export api issue failed\n");
    return 1;
  }
  (void)aegis_capability_is_allowed_at(&store, 500u, AEGIS_CAP_FS_READ, 45u);

  if (aegis_capability_audit_export_json(json, sizeof(json)) <= 0) {
    fprintf(stderr, "expected json export payload\n");
    return 1;
  }
  if (strstr(json, "\"process_id\":500") == 0 || strstr(json, "\"event_type\":4") == 0) {
    fprintf(stderr, "json export missing expected fields\n");
    return 1;
  }
  if (aegis_capability_audit_export_csv(csv, sizeof(csv)) <= 0) {
    fprintf(stderr, "expected csv export payload\n");
    return 1;
  }
  if (strstr(csv, "timestamp_epoch,process_id,requested_permissions") == 0 ||
      strstr(csv, "500") == 0) {
    fprintf(stderr, "csv export missing expected fields\n");
    return 1;
  }
  return 0;
}

static int test_capability_audit_summary_endpoint(void) {
  aegis_capability_store_t store;
  aegis_capability_audit_summary_t summary;
  char json[512];
  aegis_capability_store_init(&store);
  aegis_capability_audit_reset();
  if (aegis_capability_issue_with_ttl(&store, 550u, AEGIS_CAP_FS_READ, 70u, 20u) != 0) {
    fprintf(stderr, "summary endpoint issue failed\n");
    return 1;
  }
  (void)aegis_capability_is_allowed_at(&store, 550u, AEGIS_CAP_FS_READ, 71u);
  (void)aegis_capability_is_allowed_at(&store, 550u, AEGIS_CAP_FS_WRITE, 72u);
  if (aegis_capability_revoke(&store, 550u) != 0) {
    fprintf(stderr, "summary endpoint revoke failed\n");
    return 1;
  }
  if (aegis_capability_audit_summary_snapshot(&summary) != 0) {
    fprintf(stderr, "summary endpoint snapshot failed\n");
    return 1;
  }
  if (summary.total_events < 4u || summary.issue_events < 1u || summary.allow_events < 1u ||
      summary.deny_events < 1u || summary.revoke_events < 1u) {
    fprintf(stderr, "summary endpoint counters unexpected\n");
    return 1;
  }
  if (aegis_capability_audit_summary_json(json, sizeof(json)) <= 0 ||
      strstr(json, "\"schema_version\":1") == 0 ||
      strstr(json, "\"total_events\":") == 0 ||
      strstr(json, "\"issue_events\":") == 0 ||
      strstr(json, "\"allow_events\":") == 0 ||
      strstr(json, "\"deny_events\":") == 0) {
    fprintf(stderr, "summary endpoint json missing fields: %s\n", json);
    return 1;
  }
  return 0;
}

static int test_capability_audit_pagination_and_sink(void) {
  aegis_capability_store_t store;
  aegis_capability_audit_page_t page;
  char json_page[1024];
  char csv_page[1024];
  char sink_name[64];
  aegis_capability_store_init(&store);
  aegis_capability_audit_reset();

  if (aegis_capability_issue_with_ttl(&store, 700u, AEGIS_CAP_FS_READ, 10u, 20u) != 0) {
    fprintf(stderr, "pagination issue failed\n");
    return 1;
  }
  (void)aegis_capability_is_allowed_at(&store, 700u, AEGIS_CAP_FS_READ, 11u);
  (void)aegis_capability_is_allowed_at(&store, 700u, AEGIS_CAP_FS_WRITE, 11u);

  if (aegis_capability_audit_export_json_page(0u, 2u, json_page, sizeof(json_page), &page) <= 0) {
    fprintf(stderr, "expected paged json export\n");
    return 1;
  }
  if (page.exported_count != 2u || page.has_more == 0u || page.next_cursor < 2u) {
    fprintf(stderr, "unexpected page metadata for json export\n");
    return 1;
  }
  if (aegis_capability_audit_export_csv_page(page.next_cursor, 2u, csv_page, sizeof(csv_page), &page) <= 0) {
    fprintf(stderr, "expected paged csv export\n");
    return 1;
  }
  if (strstr(csv_page, "timestamp_epoch,process_id") == 0) {
    fprintf(stderr, "csv page missing header\n");
    return 1;
  }
  if (aegis_capability_audit_file_sink_name("cap_audit", 7u, sink_name, sizeof(sink_name)) != 0) {
    fprintf(stderr, "file sink name helper failed\n");
    return 1;
  }
  if (strcmp(sink_name, "cap_audit-0007.log") != 0) {
    fprintf(stderr, "unexpected sink name: %s\n", sink_name);
    return 1;
  }
  return 0;
}

static int test_capability_audit_retention_plan_helpers(void) {
  aegis_capability_audit_retention_plan_t plan;
  char prune_name[64];
  if (aegis_capability_audit_retention_plan(17u, 5u, &plan) != 0) {
    fprintf(stderr, "retention plan helper failed\n");
    return 1;
  }
  if (plan.keep_from_chunk_id != 13u || plan.keep_to_chunk_id != 17u || plan.prune_chunk_count != 13u) {
    fprintf(stderr, "retention plan values unexpected\n");
    return 1;
  }
  if (aegis_capability_audit_prune_candidate_name("cap_audit", 17u, 5u, 12u, prune_name,
                                                  sizeof(prune_name)) != 0) {
    fprintf(stderr, "prune candidate naming helper failed\n");
    return 1;
  }
  if (strcmp(prune_name, "cap_audit-0012.log") != 0) {
    fprintf(stderr, "unexpected prune candidate name: %s\n", prune_name);
    return 1;
  }
  if (aegis_capability_audit_prune_candidate_name("cap_audit", 17u, 5u, 13u, prune_name,
                                                  sizeof(prune_name)) == 0) {
    fprintf(stderr, "expected out-of-range prune candidate request to fail\n");
    return 1;
  }
  if (aegis_capability_audit_retention_plan(17u, 0u, &plan) == 0) {
    fprintf(stderr, "expected zero retention window to fail\n");
    return 1;
  }
  return 0;
}

static int test_capability_audit_cursor_seek_helper(void) {
  aegis_capability_store_t store;
  aegis_capability_audit_page_t page;
  char json_page[1024];
  size_t c0;
  size_t c1;
  size_t c2;
  size_t c3;
  aegis_capability_store_init(&store);
  aegis_capability_audit_reset();

  if (aegis_capability_issue_with_ttl(&store, 8001u, AEGIS_CAP_FS_READ, 100u, 30u) != 0 ||
      aegis_capability_issue_with_ttl(&store, 8002u, AEGIS_CAP_FS_READ, 200u, 30u) != 0 ||
      aegis_capability_issue_with_ttl(&store, 8003u, AEGIS_CAP_FS_READ, 300u, 30u) != 0) {
    fprintf(stderr, "cursor seek setup issue failed\n");
    return 1;
  }
  c0 = aegis_capability_audit_cursor_for_timestamp(50u);
  c1 = aegis_capability_audit_cursor_for_timestamp(150u);
  c2 = aegis_capability_audit_cursor_for_timestamp(250u);
  c3 = aegis_capability_audit_cursor_for_timestamp(350u);
  if (c0 != 0u || c1 != 1u || c2 != 2u || c3 != 3u) {
    fprintf(stderr, "unexpected cursor seek results: %llu %llu %llu %llu\n",
            (unsigned long long)c0,
            (unsigned long long)c1,
            (unsigned long long)c2,
            (unsigned long long)c3);
    return 1;
  }
  if (aegis_capability_audit_export_json_page(c1, 2u, json_page, sizeof(json_page), &page) <= 0) {
    fprintf(stderr, "cursor seek page export failed\n");
    return 1;
  }
  if (strstr(json_page, "\"process_id\":8002") == 0 || strstr(json_page, "\"process_id\":8003") == 0) {
    fprintf(stderr, "cursor seek page export missing expected events\n");
    return 1;
  }
  return 0;
}

static int test_actor_registry_snapshot_restore(void) {
  char snapshot[4096];
  aegis_actor_registry_entry_t entry;
  aegis_capability_store_t store;
  aegis_capability_store_init(&store);
  aegis_actor_registry_reset();

  if (aegis_actor_registry_register(9101u, AEGIS_ACTOR_USER, "alice_admin") != 0 ||
      aegis_actor_registry_register(9102u, AEGIS_ACTOR_SERVICE, "policyd") != 0) {
    fprintf(stderr, "snapshot restore actor registration failed\n");
    return 1;
  }
  if (aegis_actor_registry_revoke(9102u, AEGIS_ACTOR_SERVICE, 777u, "retired") != 0) {
    fprintf(stderr, "snapshot restore actor revoke failed\n");
    return 1;
  }
  if (aegis_actor_registry_snapshot(snapshot, sizeof(snapshot)) <= 0) {
    fprintf(stderr, "snapshot restore snapshot export failed\n");
    return 1;
  }
  aegis_actor_registry_reset();
  if (aegis_actor_registry_lookup(9101u, AEGIS_ACTOR_USER, &entry) == 0) {
    fprintf(stderr, "expected reset registry lookup to fail\n");
    return 1;
  }
  if (aegis_actor_registry_restore(snapshot) < 2) {
    fprintf(stderr, "snapshot restore import failed\n");
    return 1;
  }
  if (aegis_actor_registry_lookup(9101u, AEGIS_ACTOR_USER, &entry) != 0 || entry.active == 0u ||
      entry.revoked != 0u) {
    fprintf(stderr, "snapshot restore active actor lookup invalid\n");
    return 1;
  }
  if (aegis_actor_registry_lookup(9102u, AEGIS_ACTOR_SERVICE, &entry) != 0 || entry.active != 0u ||
      entry.revoked == 0u || entry.revoked_at_epoch != 777u) {
    fprintf(stderr, "snapshot restore revoked actor lookup invalid\n");
    return 1;
  }
  if (aegis_capability_issue_with_ttl(&store, 9110u, AEGIS_CAP_FS_READ, 800u, 30u) != 0) {
    fprintf(stderr, "snapshot restore issue token failed\n");
    return 1;
  }
  if (aegis_capability_rotate_with_identity(&store,
                                            9110u,
                                            AEGIS_CAP_FS_READ | AEGIS_CAP_FS_WRITE,
                                            801u,
                                            30u,
                                            9101u,
                                            AEGIS_ACTOR_USER,
                                            "alice_admin",
                                            "snapshot_roundtrip") != 0) {
    fprintf(stderr, "snapshot restore expected active actor to rotate\n");
    return 1;
  }
  if (aegis_capability_rotate_with_identity(&store,
                                            9110u,
                                            AEGIS_CAP_FS_READ,
                                            802u,
                                            30u,
                                            9102u,
                                            AEGIS_ACTOR_SERVICE,
                                            "policyd",
                                            "snapshot_revoked_should_fail") == 0) {
    fprintf(stderr, "snapshot restore expected revoked actor rotate to fail\n");
    return 1;
  }
  return 0;
}

static int test_secret_store_skeleton(void) {
  aegis_secret_store_t store;
  aegis_secret_store_t restored;
  aegis_secret_metadata_t metadata;
  const uint8_t v1[] = {1u, 2u, 3u, 4u};
  const uint8_t v2[] = {9u, 8u};
  const uint8_t v3[] = {7u, 7u, 7u};
  uint8_t out[16];
  uint32_t out_size = 0u;
  char json[256];
  char snapshot[2048];
  char tampered[2048];
  const char *duplicate_snapshot =
      "schema_version=1\n"
      "key=dup,size=1,created=1,updated=1,value=aa\n"
      "key=dup,size=1,created=2,updated=2,value=bb\n";
  const char *bad_header_snapshot =
      "schema_version=2\n"
      "key=dup,size=1,created=1,updated=1,value=aa\n";
  char oversized_snapshot[70016];
  char long_line_snapshot[768];
  size_t i = 0u;
  char inventory[512];
  uint64_t digest = 0u;
  aegis_secret_store_init(&store);
  aegis_secret_store_init(&restored);

  if (aegis_secret_put_at(&store, "db.master", v1, (uint32_t)sizeof(v1), 1000u) != 0) {
    fprintf(stderr, "secret put v1 failed\n");
    return 1;
  }
  if (aegis_secret_put_at(&store, "db.master", v2, (uint32_t)sizeof(v2), 1010u) != 0) {
    fprintf(stderr, "secret put update failed\n");
    return 1;
  }
  if (aegis_secret_put_at(&store, "api.alpha", v3, (uint32_t)sizeof(v3), 1020u) != 0) {
    fprintf(stderr, "secret put second key failed\n");
    return 1;
  }
  if (aegis_secret_metadata_get(&store, "db.master", &metadata) != 0 ||
      metadata.created_at_epoch != 1000u || metadata.updated_at_epoch != 1010u) {
    fprintf(stderr, "secret metadata get mismatch\n");
    return 1;
  }
  if (aegis_secret_get(&store, "db.master", out, (uint32_t)sizeof(out), &out_size) != 0 ||
      out_size != (uint32_t)sizeof(v2) || out[0] != 9u || out[1] != 8u) {
    fprintf(stderr, "secret get updated value mismatch\n");
    return 1;
  }
  if (aegis_secret_list_json(&store, json, sizeof(json)) <= 0 ||
      strstr(json, "\"schema_version\":1") == 0 ||
      strstr(json, "\"count\":2") == 0 ||
      strstr(json, "\"db.master\"") == 0 ||
      strstr(json, "\"api.alpha\"") == 0) {
    fprintf(stderr, "secret list json missing fields: %s\n", json);
    return 1;
  }
  if (aegis_secret_put(&store, "bad key", v1, (uint32_t)sizeof(v1)) == 0) {
    fprintf(stderr, "secret put should reject invalid key characters\n");
    return 1;
  }
  if (aegis_secret_get(&store, "db.master", out, 1u, &out_size) == 0) {
    fprintf(stderr, "secret get should reject undersized output buffer\n");
    return 1;
  }
  if (aegis_secret_snapshot_export(&store, snapshot, sizeof(snapshot)) <= 0 ||
      strstr(snapshot, "schema_version=1") == 0 ||
      strstr(snapshot, "digest=") == 0 ||
      strstr(snapshot, "key=db.master") == 0) {
    fprintf(stderr, "secret snapshot export failed\n");
    return 1;
  }
  if (aegis_secret_snapshot_digest(&store, &digest) != 0 || digest == 0u) {
    fprintf(stderr, "secret snapshot digest helper failed\n");
    return 1;
  }
  if (aegis_secret_snapshot_restore(&restored, snapshot) != 2) {
    fprintf(stderr, "secret snapshot restore failed\n");
    return 1;
  }
  if (aegis_secret_inventory_json(&restored, inventory, sizeof(inventory)) <= 0 ||
      strstr(inventory, "\"key\":\"db.master\"") == 0 ||
      strstr(inventory, "\"key\":\"api.alpha\"") == 0 ||
      strstr(inventory, "\"fingerprint64\":\"") == 0 ||
      strstr(inventory, "\"value\":") != 0) {
    fprintf(stderr, "secret inventory json invalid/redaction failed: %s\n", inventory);
    return 1;
  }
  if (strstr(inventory, "\"key\":\"api.alpha\"") > strstr(inventory, "\"key\":\"db.master\"")) {
    fprintf(stderr, "secret inventory should be sorted lexicographically: %s\n", inventory);
    return 1;
  }
  if (aegis_secret_get(&restored, "db.master", out, (uint32_t)sizeof(out), &out_size) != 0 ||
      out_size != (uint32_t)sizeof(v2) || out[0] != 9u || out[1] != 8u) {
    fprintf(stderr, "secret restored value mismatch\n");
    return 1;
  }
  if (aegis_secret_metadata_get(&restored, "db.master", &metadata) != 0 ||
      metadata.created_at_epoch != 1000u || metadata.updated_at_epoch != 1010u) {
    fprintf(stderr, "secret restored metadata mismatch\n");
    return 1;
  }
  snprintf(tampered, sizeof(tampered), "%s", snapshot);
  {
    char *value_ptr = strstr(tampered, "value=");
    if (value_ptr == 0 || value_ptr[6] == '\0') {
      fprintf(stderr, "secret tamper fixture setup failed\n");
      return 1;
    }
    value_ptr[6] = value_ptr[6] == '0' ? '1' : '0';
  }
  if (aegis_secret_snapshot_restore(&restored, tampered) >= 0) {
    fprintf(stderr, "secret snapshot restore should fail on digest mismatch\n");
    return 1;
  }
  if (aegis_secret_snapshot_restore(&restored, duplicate_snapshot) >= 0) {
    fprintf(stderr, "secret snapshot restore should fail on duplicate keys\n");
    return 1;
  }
  if (aegis_secret_snapshot_restore(&restored, bad_header_snapshot) >= 0) {
    fprintf(stderr, "secret snapshot restore should fail on bad schema header\n");
    return 1;
  }
  oversized_snapshot[0] = 's';
  for (i = 1u; i < sizeof(oversized_snapshot) - 1u; ++i) {
    oversized_snapshot[i] = 'a';
  }
  oversized_snapshot[sizeof(oversized_snapshot) - 1u] = '\0';
  if (aegis_secret_snapshot_restore(&restored, oversized_snapshot) >= 0) {
    fprintf(stderr, "secret snapshot restore should fail on oversized input\n");
    return 1;
  }
  snprintf(long_line_snapshot, sizeof(long_line_snapshot), "schema_version=1\nkey=dup,size=1,created=1,updated=1,value=");
  for (i = strlen(long_line_snapshot); i < sizeof(long_line_snapshot) - 2u; ++i) {
    long_line_snapshot[i] = 'a';
  }
  long_line_snapshot[sizeof(long_line_snapshot) - 2u] = '\n';
  long_line_snapshot[sizeof(long_line_snapshot) - 1u] = '\0';
  if (aegis_secret_snapshot_restore(&restored, long_line_snapshot) >= 0) {
    fprintf(stderr, "secret snapshot restore should fail on oversized line record\n");
    return 1;
  }
  if (aegis_secret_delete(&store, "db.master") != 0) {
    fprintf(stderr, "secret delete failed\n");
    return 1;
  }
  if (aegis_secret_delete(&store, "api.alpha") != 0 || store.count != 0u) {
    fprintf(stderr, "secret second delete failed\n");
    return 1;
  }
  if (aegis_secret_delete(&store, "db.master") == 0) {
    fprintf(stderr, "secret delete should fail for missing key\n");
    return 1;
  }
  return 0;
}

int main(void) {
  if (test_capability_validate() != 0) {
    return 1;
  }
  if (test_capability_lifecycle() != 0) {
    return 1;
  }
  if (test_capability_ttl_and_rotation() != 0) {
    return 1;
  }
  if (test_rotation_metadata_audit() != 0) {
    return 1;
  }
  if (test_rotation_identity_validation() != 0) {
    return 1;
  }
  if (test_actor_registry_and_revocation_hooks() != 0) {
    return 1;
  }
  if (test_capability_audit_pipeline() != 0) {
    return 1;
  }
  if (test_capability_audit_export_api() != 0) {
    return 1;
  }
  if (test_capability_audit_summary_endpoint() != 0) {
    return 1;
  }
  if (test_capability_audit_pagination_and_sink() != 0) {
    return 1;
  }
  if (test_capability_audit_retention_plan_helpers() != 0) {
    return 1;
  }
  if (test_capability_audit_cursor_seek_helper() != 0) {
    return 1;
  }
  if (test_actor_registry_snapshot_restore() != 0) {
    return 1;
  }
  if (test_secret_store_skeleton() != 0) {
    return 1;
  }
  puts("capability tests passed");
  return 0;
}
