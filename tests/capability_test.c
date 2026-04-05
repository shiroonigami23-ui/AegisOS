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
  if (test_capability_audit_pagination_and_sink() != 0) {
    return 1;
  }
  puts("capability tests passed");
  return 0;
}
