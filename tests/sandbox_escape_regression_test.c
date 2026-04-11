#include <stdio.h>
#include <string.h>

#include "capability.h"
#include "sandbox_engine.h"
#include "sandbox_policy.h"

static int setup_fs_process(aegis_capability_store_t *cap_store,
                            aegis_policy_engine_t *engine,
                            uint32_t process_id) {
  aegis_sandbox_policy_t policy = {
      process_id, AEGIS_CAP_FS_READ | AEGIS_CAP_FS_WRITE, 1u, 1u, 0u, 0u, 0u};
  if (aegis_capability_issue(cap_store, process_id, AEGIS_CAP_FS_READ | AEGIS_CAP_FS_WRITE) != 0) {
    return -1;
  }
  if (aegis_policy_engine_set_policy(engine, &policy) != 0) {
    return -1;
  }
  if (aegis_policy_engine_add_fs_rule(engine, process_id, "/sandbox/app", AEGIS_FS_SCOPE_READ_WRITE) != 0) {
    return -1;
  }
  return 0;
}

static int test_fs_escape_sequences_blocked(void) {
  aegis_capability_store_t cap_store;
  aegis_policy_engine_t engine;
  aegis_policy_decision_t decision;
  const uint32_t process_id = 6101u;
  const char *cases[] = {
      "/sandbox/app/../etc/passwd",
      "/sandbox/app/./config.yaml",
      "/sandbox/app/%2e%2e/etc/shadow",
      "/sandbox/app/%2Fetc/shadow",
      "/sandbox/app/%5cwindows/system32",
  };
  size_t i;

  aegis_capability_store_init(&cap_store);
  aegis_policy_engine_init(&engine);
  if (setup_fs_process(&cap_store, &engine, process_id) != 0) {
    fprintf(stderr, "escape setup failed\n");
    return 1;
  }
  for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
    if (aegis_policy_engine_check_path(&engine,
                                       &cap_store,
                                       process_id,
                                       AEGIS_ACTION_FS_READ,
                                       cases[i],
                                       &decision) != 0) {
      fprintf(stderr, "escape case should deny: %s\n", cases[i]);
      return 1;
    }
    if (strcmp(decision.reason, "filesystem path normalization guard blocked escape pattern") != 0) {
      fprintf(stderr, "escape case wrong reason for %s: %s\n", cases[i], decision.reason);
      return 1;
    }
  }
  return 0;
}

static int test_symlink_pivot_escape_blocked(void) {
  aegis_capability_store_t cap_store;
  aegis_policy_engine_t engine;
  aegis_policy_decision_t decision;
  const uint32_t process_id = 6102u;

  aegis_capability_store_init(&cap_store);
  aegis_policy_engine_init(&engine);
  if (setup_fs_process(&cap_store, &engine, process_id) != 0) {
    fprintf(stderr, "symlink setup failed\n");
    return 1;
  }
  if (aegis_policy_engine_add_symlink_rule(&engine, process_id, "/sandbox/app/link", "/etc") != 0) {
    fprintf(stderr, "symlink rule add failed\n");
    return 1;
  }
  if (aegis_policy_engine_check_path(&engine,
                                     &cap_store,
                                     process_id,
                                     AEGIS_ACTION_FS_READ,
                                     "/sandbox/app/link/shadow",
                                     &decision) != 0) {
    fprintf(stderr, "symlink pivot should deny\n");
    return 1;
  }
  if (strcmp(decision.reason, "no matching filesystem scope rule") != 0) {
    fprintf(stderr, "symlink pivot unexpected reason: %s\n", decision.reason);
    return 1;
  }
  return 0;
}

static int test_fs_legit_path_still_allowed(void) {
  aegis_capability_store_t cap_store;
  aegis_policy_engine_t engine;
  aegis_policy_decision_t decision;
  const uint32_t process_id = 6103u;

  aegis_capability_store_init(&cap_store);
  aegis_policy_engine_init(&engine);
  if (setup_fs_process(&cap_store, &engine, process_id) != 0) {
    fprintf(stderr, "legit setup failed\n");
    return 1;
  }
  if (aegis_policy_engine_check_path(&engine,
                                     &cap_store,
                                     process_id,
                                     AEGIS_ACTION_FS_WRITE,
                                     "/sandbox/app/config/state.json",
                                     &decision) != 1) {
    fprintf(stderr, "legit path expected allow: %s\n", decision.reason);
    return 1;
  }
  return 0;
}

static int test_dns_escape_regression_cases(void) {
  aegis_capability_store_t cap_store;
  aegis_policy_engine_t engine;
  aegis_policy_decision_t decision;
  const uint32_t process_id = 6201u;
  const uint32_t pinned_v4 = 0x0A64000Au; /* 10.100.0.10 */
  const char *pinned_v6 = "2001:db8::64";
  aegis_sandbox_policy_t policy = {
      process_id, AEGIS_CAP_NET_CLIENT, 0u, 0u, 1u, 0u, 0u};

  aegis_capability_store_init(&cap_store);
  aegis_policy_engine_init(&engine);
  if (aegis_capability_issue(&cap_store, process_id, AEGIS_CAP_NET_CLIENT) != 0) {
    fprintf(stderr, "dns capability setup failed\n");
    return 1;
  }
  if (aegis_policy_engine_set_policy(&engine, &policy) != 0) {
    fprintf(stderr, "dns policy setup failed\n");
    return 1;
  }
  if (aegis_policy_engine_add_net_rule(&engine,
                                       process_id,
                                       "api.escape.local",
                                       443,
                                       443,
                                       AEGIS_NET_PROTO_TCP,
                                       1u,
                                       0u,
                                       1u) != 0) {
    fprintf(stderr, "dns net rule setup failed\n");
    return 1;
  }
  if (aegis_policy_engine_pin_dns_ipv4(&engine, process_id, "api.escape.local", pinned_v4) != 0 ||
      aegis_policy_engine_pin_dns_ipv6(&engine, process_id, "api.escape.local", pinned_v6) != 0 ||
      aegis_policy_engine_set_dns_dual_stack_strict(&engine, process_id, "api.escape.local", 1u) != 0) {
    fprintf(stderr, "dns pin setup failed\n");
    return 1;
  }
  if (aegis_policy_engine_check_network_with_ip_ex(&engine,
                                                   &cap_store,
                                                   process_id,
                                                   AEGIS_ACTION_NET_CONNECT,
                                                   "api.escape.local",
                                                   443,
                                                   AEGIS_NET_PROTO_TCP,
                                                   pinned_v4,
                                                   0,
                                                   &decision) != 0) {
    fprintf(stderr, "dns strict gate should deny missing address family\n");
    return 1;
  }
  if (strcmp(decision.reason, "dns dual-stack strict mode requires both ipv4 and ipv6 resolution") != 0) {
    fprintf(stderr, "dns strict reason mismatch: %s\n", decision.reason);
    return 1;
  }
  if (aegis_policy_engine_check_network_with_ip_ex(&engine,
                                                   &cap_store,
                                                   process_id,
                                                   AEGIS_ACTION_NET_CONNECT,
                                                   "api.escape.local",
                                                   443,
                                                   AEGIS_NET_PROTO_TCP,
                                                   0x0A64000Bu,
                                                   pinned_v6,
                                                   &decision) != 0) {
    fprintf(stderr, "dns pin mismatch should deny\n");
    return 1;
  }
  if (strcmp(decision.reason, "dns rebinding guard blocked host/ip mismatch") != 0) {
    fprintf(stderr, "dns pin mismatch reason mismatch: %s\n", decision.reason);
    return 1;
  }
  return 0;
}

int main(void) {
  if (test_fs_escape_sequences_blocked() != 0) {
    return 1;
  }
  if (test_symlink_pivot_escape_blocked() != 0) {
    return 1;
  }
  if (test_fs_legit_path_still_allowed() != 0) {
    return 1;
  }
  if (test_dns_escape_regression_cases() != 0) {
    return 1;
  }
  puts("sandbox escape regression suite passed");
  return 0;
}
