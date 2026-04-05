#include <stdio.h>
#include <string.h>

#include "capability.h"
#include "sandbox_engine.h"
#include "sandbox_policy.h"

static int test_allow_path(void) {
  aegis_capability_store_t cap_store;
  aegis_policy_engine_t engine;
  aegis_sandbox_policy_t policy = {
      2001u, AEGIS_CAP_FS_READ | AEGIS_CAP_NET_CLIENT, 1u, 0u, 1u, 0u, 0u};
  aegis_policy_decision_t decision;

  aegis_capability_store_init(&cap_store);
  aegis_policy_engine_init(&engine);

  if (aegis_capability_issue(&cap_store, 2001u, AEGIS_CAP_FS_READ | AEGIS_CAP_NET_CLIENT) != 0) {
    fprintf(stderr, "capability issue failed\n");
    return 1;
  }
  if (aegis_policy_engine_set_policy(&engine, &policy) != 0) {
    fprintf(stderr, "set policy failed\n");
    return 1;
  }
  if (aegis_policy_engine_check(&engine, &cap_store, 2001u, AEGIS_ACTION_FS_READ, &decision) != 1) {
    fprintf(stderr, "expected FS_READ allow, got: %s\n", decision.reason);
    return 1;
  }
  if (decision.allowed == 0) {
    fprintf(stderr, "decision.allowed should be true\n");
    return 1;
  }
  return 0;
}

static int test_deny_missing_capability(void) {
  aegis_capability_store_t cap_store;
  aegis_policy_engine_t engine;
  aegis_sandbox_policy_t policy = {
      2002u, AEGIS_CAP_FS_READ | AEGIS_CAP_FS_WRITE, 1u, 1u, 0u, 0u, 0u};
  aegis_policy_decision_t decision;

  aegis_capability_store_init(&cap_store);
  aegis_policy_engine_init(&engine);

  if (aegis_capability_issue(&cap_store, 2002u, AEGIS_CAP_FS_READ) != 0) {
    fprintf(stderr, "capability issue failed\n");
    return 1;
  }
  if (aegis_policy_engine_set_policy(&engine, &policy) != 0) {
    fprintf(stderr, "set policy failed\n");
    return 1;
  }
  if (aegis_policy_engine_check(&engine, &cap_store, 2002u, AEGIS_ACTION_FS_WRITE, &decision) != 0) {
    fprintf(stderr, "expected FS_WRITE deny path\n");
    return 1;
  }
  if (strcmp(decision.reason, "missing capability token permission") != 0) {
    fprintf(stderr, "unexpected reason: %s\n", decision.reason);
    return 1;
  }
  return 0;
}

static int test_deny_policy_gate(void) {
  aegis_capability_store_t cap_store;
  aegis_policy_engine_t engine;
  aegis_sandbox_policy_t policy = {
      2003u, AEGIS_CAP_DEVICE_IO, 0u, 0u, 0u, 0u, 0u};
  aegis_policy_decision_t decision;

  aegis_capability_store_init(&cap_store);
  aegis_policy_engine_init(&engine);

  if (aegis_capability_issue(&cap_store, 2003u, AEGIS_CAP_DEVICE_IO) != 0) {
    fprintf(stderr, "capability issue failed\n");
    return 1;
  }
  if (aegis_policy_engine_set_policy(&engine, &policy) != 0) {
    fprintf(stderr, "set policy failed\n");
    return 1;
  }
  if (aegis_policy_engine_check(&engine, &cap_store, 2003u, AEGIS_ACTION_DEVICE_IO, &decision) != 0) {
    fprintf(stderr, "expected DEVICE_IO deny path\n");
    return 1;
  }
  if (strcmp(decision.reason, "blocked by sandbox policy gate") != 0) {
    fprintf(stderr, "unexpected reason: %s\n", decision.reason);
    return 1;
  }
  return 0;
}

static int test_path_scope_read_only_and_read_write(void) {
  aegis_capability_store_t cap_store;
  aegis_policy_engine_t engine;
  aegis_sandbox_policy_t policy = {
      3001u, AEGIS_CAP_FS_READ | AEGIS_CAP_FS_WRITE, 1u, 1u, 0u, 0u, 0u};
  aegis_policy_decision_t decision;

  aegis_capability_store_init(&cap_store);
  aegis_policy_engine_init(&engine);
  if (aegis_capability_issue(&cap_store, 3001u, AEGIS_CAP_FS_READ | AEGIS_CAP_FS_WRITE) != 0) {
    fprintf(stderr, "capability issue failed for path test\n");
    return 1;
  }
  if (aegis_policy_engine_set_policy(&engine, &policy) != 0) {
    fprintf(stderr, "set policy failed for path test\n");
    return 1;
  }
  if (aegis_policy_engine_add_fs_rule(&engine, 3001u, "/home/user/docs", AEGIS_FS_SCOPE_READ_ONLY) != 0) {
    fprintf(stderr, "add read-only scope failed\n");
    return 1;
  }
  if (aegis_policy_engine_check_path(
          &engine, &cap_store, 3001u, AEGIS_ACTION_FS_READ, "/home/user/docs/file.txt", &decision) != 1) {
    fprintf(stderr, "expected read allow in read-only scope, got: %s\n", decision.reason);
    return 1;
  }
  if (aegis_policy_engine_check_path(
          &engine, &cap_store, 3001u, AEGIS_ACTION_FS_WRITE, "/home/user/docs/file.txt", &decision) != 0) {
    fprintf(stderr, "expected write deny in read-only scope\n");
    return 1;
  }
  if (strcmp(decision.reason, "write blocked by read-only filesystem scope") != 0) {
    fprintf(stderr, "unexpected reason for write deny: %s\n", decision.reason);
    return 1;
  }
  if (aegis_policy_engine_add_fs_rule(&engine, 3001u, "/home/user", AEGIS_FS_SCOPE_READ_WRITE) != 0) {
    fprintf(stderr, "add read-write scope failed\n");
    return 1;
  }
  if (aegis_policy_engine_check_path(
          &engine, &cap_store, 3001u, AEGIS_ACTION_FS_WRITE, "/home/user/notes.txt", &decision) != 1) {
    fprintf(stderr, "expected write allow in read-write scope, got: %s\n", decision.reason);
    return 1;
  }
  return 0;
}

static int test_path_scope_deny_override(void) {
  aegis_capability_store_t cap_store;
  aegis_policy_engine_t engine;
  aegis_sandbox_policy_t policy = {
      3002u, AEGIS_CAP_FS_READ | AEGIS_CAP_FS_WRITE, 1u, 1u, 0u, 0u, 0u};
  aegis_policy_decision_t decision;

  aegis_capability_store_init(&cap_store);
  aegis_policy_engine_init(&engine);
  if (aegis_capability_issue(&cap_store, 3002u, AEGIS_CAP_FS_READ | AEGIS_CAP_FS_WRITE) != 0) {
    fprintf(stderr, "capability issue failed for deny override test\n");
    return 1;
  }
  if (aegis_policy_engine_set_policy(&engine, &policy) != 0) {
    fprintf(stderr, "set policy failed for deny override test\n");
    return 1;
  }
  if (aegis_policy_engine_add_fs_rule(&engine, 3002u, "/home", AEGIS_FS_SCOPE_READ_WRITE) != 0) {
    fprintf(stderr, "add broad scope failed\n");
    return 1;
  }
  if (aegis_policy_engine_add_fs_rule(&engine, 3002u, "/home/private", AEGIS_FS_SCOPE_DENY) != 0) {
    fprintf(stderr, "add deny scope failed\n");
    return 1;
  }
  if (aegis_policy_engine_check_path(
          &engine, &cap_store, 3002u, AEGIS_ACTION_FS_READ, "/home/private/secret.txt", &decision) != 0) {
    fprintf(stderr, "expected deny override to block read\n");
    return 1;
  }
  if (strcmp(decision.reason, "denied by filesystem scope rule") != 0) {
    fprintf(stderr, "unexpected deny override reason: %s\n", decision.reason);
    return 1;
  }
  if (aegis_policy_engine_check_path(
          &engine, &cap_store, 3002u, AEGIS_ACTION_FS_READ, "/var/log/syslog", &decision) != 0) {
    fprintf(stderr, "expected no matching rule deny\n");
    return 1;
  }
  if (strcmp(decision.reason, "no matching filesystem scope rule") != 0) {
    fprintf(stderr, "unexpected no-match reason: %s\n", decision.reason);
    return 1;
  }
  return 0;
}

static int test_network_scope_allow_and_deny(void) {
  aegis_capability_store_t cap_store;
  aegis_policy_engine_t engine;
  aegis_sandbox_policy_t policy = {
      4001u, AEGIS_CAP_NET_CLIENT | AEGIS_CAP_NET_SERVER, 0u, 0u, 1u, 1u, 0u};
  aegis_policy_decision_t decision;

  aegis_capability_store_init(&cap_store);
  aegis_policy_engine_init(&engine);

  if (aegis_capability_issue(&cap_store, 4001u, AEGIS_CAP_NET_CLIENT | AEGIS_CAP_NET_SERVER) != 0) {
    fprintf(stderr, "capability issue failed for network test\n");
    return 1;
  }
  if (aegis_policy_engine_set_policy(&engine, &policy) != 0) {
    fprintf(stderr, "set policy failed for network test\n");
    return 1;
  }
  if (aegis_policy_engine_add_net_rule(
          &engine, 4001u, "*.trusted.local", 443, 443, AEGIS_NET_PROTO_TCP, 1u, 0u, 1u) != 0) {
    fprintf(stderr, "failed to add trusted allow rule\n");
    return 1;
  }
  if (aegis_policy_engine_add_net_rule(
          &engine, 4001u, "*.trusted.local", 1, 65535, AEGIS_NET_PROTO_ANY, 1u, 1u, 0u) != 0) {
    fprintf(stderr, "failed to add deny override rule\n");
    return 1;
  }
  if (aegis_policy_engine_check_network(&engine,
                                        &cap_store,
                                        4001u,
                                        AEGIS_ACTION_NET_CONNECT,
                                        "api.trusted.local",
                                        443,
                                        AEGIS_NET_PROTO_TCP,
                                        &decision) != 1) {
    fprintf(stderr, "expected specific allow to beat broad deny for trusted host 443\n");
    return 1;
  }
  if (strcmp(decision.reason, "allowed by network scope") != 0) {
    fprintf(stderr, "unexpected allow reason: %s\n", decision.reason);
    return 1;
  }
  if (aegis_policy_engine_clear_net_rules(&engine, 4001u) != 0) {
    fprintf(stderr, "failed to clear net rules\n");
    return 1;
  }
  if (aegis_policy_engine_add_net_rule(
          &engine, 4001u, "*.trusted.local", 443, 443, AEGIS_NET_PROTO_TCP, 1u, 0u, 1u) != 0) {
    fprintf(stderr, "failed to add allow rule after clear\n");
    return 1;
  }
  if (aegis_policy_engine_check_network(&engine,
                                        &cap_store,
                                        4001u,
                                        AEGIS_ACTION_NET_CONNECT,
                                        "api.trusted.local",
                                        443,
                                        AEGIS_NET_PROTO_TCP,
                                        &decision) != 1) {
    fprintf(stderr, "expected allow for trusted host 443, got: %s\n", decision.reason);
    return 1;
  }
  if (aegis_policy_engine_check_network(&engine,
                                        &cap_store,
                                        4001u,
                                        AEGIS_ACTION_NET_CONNECT,
                                        "api.trusted.local",
                                        8443,
                                        AEGIS_NET_PROTO_TCP,
                                        &decision) != 0) {
    fprintf(stderr, "expected no-match deny for 8443\n");
    return 1;
  }
  if (strcmp(decision.reason, "no matching network scope rule") != 0) {
    fprintf(stderr, "unexpected no-match reason: %s\n", decision.reason);
    return 1;
  }
  return 0;
}

static int test_network_scope_tie_break_deny(void) {
  aegis_capability_store_t cap_store;
  aegis_policy_engine_t engine;
  aegis_sandbox_policy_t policy = {
      4002u, AEGIS_CAP_NET_CLIENT, 0u, 0u, 1u, 0u, 0u};
  aegis_policy_decision_t decision;

  aegis_capability_store_init(&cap_store);
  aegis_policy_engine_init(&engine);
  if (aegis_capability_issue(&cap_store, 4002u, AEGIS_CAP_NET_CLIENT) != 0) {
    fprintf(stderr, "capability issue failed for tie-break test\n");
    return 1;
  }
  if (aegis_policy_engine_set_policy(&engine, &policy) != 0) {
    fprintf(stderr, "set policy failed for tie-break test\n");
    return 1;
  }
  if (aegis_policy_engine_add_net_rule(
          &engine, 4002u, "api.example.local", 443, 443, AEGIS_NET_PROTO_TCP, 1u, 0u, 1u) != 0) {
    fprintf(stderr, "failed to add allow tie rule\n");
    return 1;
  }
  if (aegis_policy_engine_add_net_rule(
          &engine, 4002u, "api.example.local", 443, 443, AEGIS_NET_PROTO_TCP, 1u, 0u, 0u) != 0) {
    fprintf(stderr, "failed to add deny tie rule\n");
    return 1;
  }
  if (aegis_policy_engine_check_network(&engine,
                                        &cap_store,
                                        4002u,
                                        AEGIS_ACTION_NET_CONNECT,
                                        "api.example.local",
                                        443,
                                        AEGIS_NET_PROTO_TCP,
                                        &decision) != 0) {
    fprintf(stderr, "expected deny tie-break outcome\n");
    return 1;
  }
  if (strcmp(decision.reason, "denied by network scope rule") != 0) {
    fprintf(stderr, "unexpected tie-break reason: %s\n", decision.reason);
    return 1;
  }
  return 0;
}

static int test_symlink_scope_resolution(void) {
  aegis_capability_store_t cap_store;
  aegis_policy_engine_t engine;
  aegis_sandbox_policy_t policy = {
      5001u, AEGIS_CAP_FS_READ, 1u, 0u, 0u, 0u, 0u};
  aegis_policy_decision_t decision;

  aegis_capability_store_init(&cap_store);
  aegis_policy_engine_init(&engine);

  if (aegis_capability_issue(&cap_store, 5001u, AEGIS_CAP_FS_READ) != 0) {
    fprintf(stderr, "capability issue failed for symlink test\n");
    return 1;
  }
  if (aegis_policy_engine_set_policy(&engine, &policy) != 0) {
    fprintf(stderr, "set policy failed for symlink test\n");
    return 1;
  }
  if (aegis_policy_engine_add_fs_rule(&engine, 5001u, "/safe", AEGIS_FS_SCOPE_READ_WRITE) != 0) {
    fprintf(stderr, "add safe fs scope failed\n");
    return 1;
  }
  if (aegis_policy_engine_add_fs_rule(&engine, 5001u, "/secret", AEGIS_FS_SCOPE_DENY) != 0) {
    fprintf(stderr, "add secret deny scope failed\n");
    return 1;
  }
  if (aegis_policy_engine_add_symlink_rule(&engine, 5001u, "/safe/link", "/secret") != 0) {
    fprintf(stderr, "add symlink rule failed\n");
    return 1;
  }
  if (aegis_policy_engine_check_path(
          &engine, &cap_store, 5001u, AEGIS_ACTION_FS_READ, "/safe/link/data.txt", &decision) != 0) {
    fprintf(stderr, "expected symlink-resolved path to be denied\n");
    return 1;
  }
  if (strcmp(decision.reason, "denied by filesystem scope rule") != 0) {
    fprintf(stderr, "unexpected symlink deny reason: %s\n", decision.reason);
    return 1;
  }
  return 0;
}

static int test_filesystem_wildcard_scope(void) {
  aegis_capability_store_t cap_store;
  aegis_policy_engine_t engine;
  aegis_sandbox_policy_t policy = {
      5100u, AEGIS_CAP_FS_READ | AEGIS_CAP_FS_WRITE, 1u, 1u, 0u, 0u, 0u};
  aegis_policy_decision_t decision;

  aegis_capability_store_init(&cap_store);
  aegis_policy_engine_init(&engine);
  if (aegis_capability_issue(&cap_store, 5100u, AEGIS_CAP_FS_READ | AEGIS_CAP_FS_WRITE) != 0) {
    fprintf(stderr, "wildcard capability issue failed\n");
    return 1;
  }
  if (aegis_policy_engine_set_policy(&engine, &policy) != 0) {
    fprintf(stderr, "wildcard policy set failed\n");
    return 1;
  }
  if (aegis_policy_engine_add_fs_rule(&engine, 5100u, "/home/*/public/*", AEGIS_FS_SCOPE_READ_WRITE) != 0) {
    fprintf(stderr, "wildcard fs rule add failed\n");
    return 1;
  }
  if (aegis_policy_engine_check_path(&engine,
                                     &cap_store,
                                     5100u,
                                     AEGIS_ACTION_FS_WRITE,
                                     "/home/alice/public/file.txt",
                                     &decision) != 1) {
    fprintf(stderr, "expected wildcard write allow, got: %s\n", decision.reason);
    return 1;
  }
  if (aegis_policy_engine_check_path(&engine,
                                     &cap_store,
                                     5100u,
                                     AEGIS_ACTION_FS_READ,
                                     "/home/alice/private/file.txt",
                                     &decision) != 0) {
    fprintf(stderr, "expected wildcard no-match deny\n");
    return 1;
  }
  if (strcmp(decision.reason, "no matching filesystem scope rule") != 0) {
    fprintf(stderr, "unexpected wildcard deny reason: %s\n", decision.reason);
    return 1;
  }
  return 0;
}

static int test_dns_rebinding_guard(void) {
  aegis_capability_store_t cap_store;
  aegis_policy_engine_t engine;
  aegis_sandbox_policy_t policy = {
      5200u, AEGIS_CAP_NET_CLIENT, 0u, 0u, 1u, 0u, 0u};
  aegis_policy_decision_t decision;
  const uint32_t pinned_ip = 0xC0A8010A;   /* 192.168.1.10 */
  const uint32_t other_ip = 0x0A000005;    /* 10.0.0.5 */

  aegis_capability_store_init(&cap_store);
  aegis_policy_engine_init(&engine);
  if (aegis_capability_issue(&cap_store, 5200u, AEGIS_CAP_NET_CLIENT) != 0) {
    fprintf(stderr, "dns guard capability issue failed\n");
    return 1;
  }
  if (aegis_policy_engine_set_policy(&engine, &policy) != 0) {
    fprintf(stderr, "dns guard set policy failed\n");
    return 1;
  }
  if (aegis_policy_engine_add_net_rule(
          &engine, 5200u, "api.safe.local", 443, 443, AEGIS_NET_PROTO_TCP, 1u, 0u, 1u) != 0) {
    fprintf(stderr, "dns guard add net rule failed\n");
    return 1;
  }
  if (aegis_policy_engine_pin_dns_ipv4(&engine, 5200u, "api.safe.local", pinned_ip) != 0) {
    fprintf(stderr, "dns guard pin failed\n");
    return 1;
  }
  if (aegis_policy_engine_check_network_with_ip(&engine,
                                                &cap_store,
                                                5200u,
                                                AEGIS_ACTION_NET_CONNECT,
                                                "api.safe.local",
                                                443,
                                                AEGIS_NET_PROTO_TCP,
                                                pinned_ip,
                                                &decision) != 1) {
    fprintf(stderr, "expected pinned ip allow, got: %s\n", decision.reason);
    return 1;
  }
  if (aegis_policy_engine_check_network_with_ip(&engine,
                                                &cap_store,
                                                5200u,
                                                AEGIS_ACTION_NET_CONNECT,
                                                "api.safe.local",
                                                443,
                                                AEGIS_NET_PROTO_TCP,
                                                other_ip,
                                                &decision) != 0) {
    fprintf(stderr, "expected pinned ip mismatch deny\n");
    return 1;
  }
  if (strcmp(decision.reason, "dns rebinding guard blocked host/ip mismatch") != 0) {
    fprintf(stderr, "unexpected dns guard reason: %s\n", decision.reason);
    return 1;
  }
  return 0;
}

static int test_policy_hot_reload(void) {
  aegis_capability_store_t cap_store;
  aegis_policy_engine_t engine;
  aegis_sandbox_policy_t initial = {
      5300u, AEGIS_CAP_FS_READ | AEGIS_CAP_FS_WRITE, 1u, 0u, 0u, 0u, 0u};
  aegis_sandbox_policy_t updated = {
      5300u, AEGIS_CAP_FS_READ | AEGIS_CAP_FS_WRITE, 1u, 1u, 0u, 0u, 0u};
  aegis_sandbox_policy_t invalid = {
      5300u, AEGIS_CAP_FS_READ, 1u, 1u, 0u, 0u, 0u};
  aegis_policy_decision_t decision;

  aegis_capability_store_init(&cap_store);
  aegis_policy_engine_init(&engine);
  if (aegis_capability_issue(&cap_store, 5300u, AEGIS_CAP_FS_READ | AEGIS_CAP_FS_WRITE) != 0) {
    fprintf(stderr, "hot reload capability issue failed\n");
    return 1;
  }
  if (aegis_policy_engine_set_policy(&engine, &initial) != 0) {
    fprintf(stderr, "hot reload initial set failed\n");
    return 1;
  }
  if (aegis_policy_engine_check(&engine, &cap_store, 5300u, AEGIS_ACTION_FS_WRITE, &decision) != 0) {
    fprintf(stderr, "expected initial write deny by policy gate\n");
    return 1;
  }
  if (aegis_policy_engine_hot_reload_policy(&engine, &updated) != 0) {
    fprintf(stderr, "hot reload valid update failed\n");
    return 1;
  }
  if (aegis_policy_engine_check(&engine, &cap_store, 5300u, AEGIS_ACTION_FS_WRITE, &decision) != 1) {
    fprintf(stderr, "expected write allow after hot reload\n");
    return 1;
  }
  if (aegis_policy_engine_hot_reload_policy(&engine, &invalid) == 0) {
    fprintf(stderr, "expected invalid hot reload to fail\n");
    return 1;
  }
  if (aegis_policy_engine_check(&engine, &cap_store, 5300u, AEGIS_ACTION_FS_WRITE, &decision) != 1) {
    fprintf(stderr, "expected previous valid policy to remain active\n");
    return 1;
  }
  return 0;
}

int main(void) {
  if (test_allow_path() != 0) {
    return 1;
  }
  if (test_deny_missing_capability() != 0) {
    return 1;
  }
  if (test_deny_policy_gate() != 0) {
    return 1;
  }
  if (test_path_scope_read_only_and_read_write() != 0) {
    return 1;
  }
  if (test_path_scope_deny_override() != 0) {
    return 1;
  }
  if (test_network_scope_allow_and_deny() != 0) {
    return 1;
  }
  if (test_network_scope_tie_break_deny() != 0) {
    return 1;
  }
  if (test_symlink_scope_resolution() != 0) {
    return 1;
  }
  if (test_filesystem_wildcard_scope() != 0) {
    return 1;
  }
  if (test_dns_rebinding_guard() != 0) {
    return 1;
  }
  if (test_policy_hot_reload() != 0) {
    return 1;
  }
  puts("sandbox engine tests passed");
  return 0;
}
