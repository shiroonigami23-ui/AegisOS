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

static int test_network_scope_debug_trace(void) {
  aegis_capability_store_t cap_store;
  aegis_policy_engine_t engine;
  aegis_sandbox_policy_t policy = {
      4003u, AEGIS_CAP_NET_CLIENT, 0u, 0u, 1u, 0u, 0u};
  aegis_policy_decision_t decision;
  char trace[1024];

  aegis_capability_store_init(&cap_store);
  aegis_policy_engine_init(&engine);
  if (aegis_capability_issue(&cap_store, 4003u, AEGIS_CAP_NET_CLIENT) != 0) {
    fprintf(stderr, "trace capability issue failed\n");
    return 1;
  }
  if (aegis_policy_engine_set_policy(&engine, &policy) != 0) {
    fprintf(stderr, "trace set policy failed\n");
    return 1;
  }
  if (aegis_policy_engine_add_net_rule(
          &engine, 4003u, "*.trace.local", 443, 443, AEGIS_NET_PROTO_TCP, 1u, 0u, 1u) != 0) {
    fprintf(stderr, "trace add allow rule failed\n");
    return 1;
  }
  if (aegis_policy_engine_add_net_rule(
          &engine, 4003u, "*.trace.local", 443, 443, AEGIS_NET_PROTO_TCP, 1u, 1u, 0u) != 0) {
    fprintf(stderr, "trace add deny tie rule failed\n");
    return 1;
  }
  if (aegis_policy_engine_check_network_with_ip_trace(&engine,
                                                      &cap_store,
                                                      4003u,
                                                      AEGIS_ACTION_NET_CONNECT,
                                                      "api.trace.local",
                                                      443,
                                                      AEGIS_NET_PROTO_TCP,
                                                      0u,
                                                      0,
                                                      trace,
                                                      sizeof(trace),
                                                      &decision) != 0) {
    fprintf(stderr, "expected trace path deny due to tie-break\n");
    return 1;
  }
  if (strstr(trace, "winner=rule[") == 0 || strstr(trace, "tie-break=deny") == 0) {
    fprintf(stderr, "trace missing winner or tie-break details: %s\n", trace);
    return 1;
  }
  return 0;
}

static int test_network_scope_debug_trace_json(void) {
  aegis_capability_store_t cap_store;
  aegis_policy_engine_t engine;
  aegis_sandbox_policy_t policy = {
      4004u, AEGIS_CAP_NET_CLIENT, 0u, 0u, 1u, 0u, 0u};
  aegis_policy_decision_t decision;
  char json_trace[1024];

  aegis_capability_store_init(&cap_store);
  aegis_policy_engine_init(&engine);
  if (aegis_capability_issue(&cap_store, 4004u, AEGIS_CAP_NET_CLIENT) != 0) {
    fprintf(stderr, "json trace capability issue failed\n");
    return 1;
  }
  if (aegis_policy_engine_set_policy(&engine, &policy) != 0) {
    fprintf(stderr, "json trace set policy failed\n");
    return 1;
  }
  if (aegis_policy_engine_add_net_rule(
          &engine, 4004u, "*.tracejson.local", 443, 443, AEGIS_NET_PROTO_TCP, 1u, 0u, 1u) != 0) {
    fprintf(stderr, "json trace add allow rule failed\n");
    return 1;
  }
  if (aegis_policy_engine_add_net_rule(
          &engine, 4004u, "*.tracejson.local", 443, 443, AEGIS_NET_PROTO_TCP, 1u, 1u, 0u) != 0) {
    fprintf(stderr, "json trace add deny tie rule failed\n");
    return 1;
  }
  if (aegis_policy_engine_check_network_with_ip_trace_json(&engine,
                                                           &cap_store,
                                                           4004u,
                                                           AEGIS_ACTION_NET_CONNECT,
                                                           "api.tracejson.local",
                                                           443,
                                                           AEGIS_NET_PROTO_TCP,
                                                           0u,
                                                           0,
                                                           json_trace,
                                                           sizeof(json_trace),
                                                           &decision) != 0) {
    fprintf(stderr, "expected json trace deny due to tie-break\n");
    return 1;
  }
  if (strstr(json_trace, "\"matched_rules\":2") == 0 ||
      strstr(json_trace, "\"tie_break_deny\":1") == 0 ||
      strstr(json_trace, "\"decision_allowed\":0") == 0 ||
      strstr(json_trace, "\"winner_rule_index\":") == 0) {
    fprintf(stderr, "json trace missing expected fields: %s\n", json_trace);
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

static int test_filesystem_wildcard_validation_rules(void) {
  aegis_policy_engine_t engine;
  aegis_policy_engine_init(&engine);
  if (aegis_policy_engine_add_fs_rule(&engine, 6100u, "/ok/*/public/*", AEGIS_FS_SCOPE_READ_ONLY) != 0) {
    fprintf(stderr, "expected valid wildcard rule to pass\n");
    return 1;
  }
  if (aegis_policy_engine_add_fs_rule(&engine, 6100u, "relative/path/*", AEGIS_FS_SCOPE_READ_ONLY) == 0) {
    fprintf(stderr, "expected relative path rule to fail\n");
    return 1;
  }
  if (aegis_policy_engine_add_fs_rule(&engine, 6100u, "/bad/**/path", AEGIS_FS_SCOPE_READ_ONLY) == 0) {
    fprintf(stderr, "expected consecutive wildcard rule to fail\n");
    return 1;
  }
  if (aegis_policy_engine_add_fs_rule(&engine, 6100u, "/bad/pre*fix/path", AEGIS_FS_SCOPE_READ_ONLY) == 0) {
    fprintf(stderr, "expected inline wildcard segment to fail\n");
    return 1;
  }
  if (aegis_policy_engine_add_fs_rule(&engine, 6100u, "/bad/../escape", AEGIS_FS_SCOPE_READ_ONLY) == 0) {
    fprintf(stderr, "expected traversal-like rule to fail\n");
    return 1;
  }
  return 0;
}

static int test_filesystem_wildcard_lint_and_compile(void) {
  aegis_fs_pattern_lint_t lint;
  char compiled[128];
  char diagnostic[96];
  if (aegis_policy_engine_lint_fs_scope_pattern("/home/*/public/*", &lint) != 1) {
    fprintf(stderr, "expected wildcard lint to pass\n");
    return 1;
  }
  if (lint.valid == 0 || lint.has_wildcards == 0 || lint.wildcard_segments != 2u) {
    fprintf(stderr, "unexpected lint summary for wildcard pattern\n");
    return 1;
  }
  if (strcmp(lint.normalized_pattern, "/home/*/public/*") != 0) {
    fprintf(stderr, "unexpected normalized wildcard pattern: %s\n", lint.normalized_pattern);
    return 1;
  }
  if (aegis_policy_engine_compile_fs_scope_pattern(
          "/home/*/public/*", compiled, sizeof(compiled), diagnostic, sizeof(diagnostic)) != 0) {
    fprintf(stderr, "expected wildcard compile to pass: %s\n", diagnostic);
    return 1;
  }
  if (strcmp(compiled, "/home/*/public/*") != 0) {
    fprintf(stderr, "unexpected compiled pattern: %s\n", compiled);
    return 1;
  }
  if (aegis_policy_engine_lint_fs_scope_pattern("/bad/pre*fix/path", &lint) != 0) {
    fprintf(stderr, "expected inline wildcard lint to fail\n");
    return 1;
  }
  if (strstr(lint.diagnostic, "wildcard must") == 0) {
    fprintf(stderr, "expected lint diagnostic for inline wildcard: %s\n", lint.diagnostic);
    return 1;
  }
  if (aegis_policy_engine_compile_fs_scope_pattern(
          "/bad/../escape", compiled, sizeof(compiled), diagnostic, sizeof(diagnostic)) == 0) {
    fprintf(stderr, "expected traversal compile to fail\n");
    return 1;
  }
  if (strstr(diagnostic, "must not contain '..'") == 0) {
    fprintf(stderr, "unexpected traversal compile diagnostic: %s\n", diagnostic);
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

static int test_dns_rebinding_guard_ipv6(void) {
  aegis_capability_store_t cap_store;
  aegis_policy_engine_t engine;
  aegis_sandbox_policy_t policy = {
      5201u, AEGIS_CAP_NET_CLIENT, 0u, 0u, 1u, 0u, 0u};
  aegis_policy_decision_t decision;
  const char *pinned_v6 = "2001:db8::10";
  const char *other_v6 = "2001:db8::11";

  aegis_capability_store_init(&cap_store);
  aegis_policy_engine_init(&engine);
  if (aegis_capability_issue(&cap_store, 5201u, AEGIS_CAP_NET_CLIENT) != 0) {
    fprintf(stderr, "dns ipv6 capability issue failed\n");
    return 1;
  }
  if (aegis_policy_engine_set_policy(&engine, &policy) != 0) {
    fprintf(stderr, "dns ipv6 set policy failed\n");
    return 1;
  }
  if (aegis_policy_engine_add_net_rule(
          &engine, 5201u, "api.safe6.local", 443, 443, AEGIS_NET_PROTO_TCP, 1u, 0u, 1u) != 0) {
    fprintf(stderr, "dns ipv6 add net rule failed\n");
    return 1;
  }
  if (aegis_policy_engine_pin_dns_ipv6(&engine, 5201u, "api.safe6.local", pinned_v6) != 0) {
    fprintf(stderr, "dns ipv6 pin failed\n");
    return 1;
  }
  if (aegis_policy_engine_check_network_with_ip_ex(&engine,
                                                   &cap_store,
                                                   5201u,
                                                   AEGIS_ACTION_NET_CONNECT,
                                                   "api.safe6.local",
                                                   443,
                                                   AEGIS_NET_PROTO_TCP,
                                                   0u,
                                                   pinned_v6,
                                                   &decision) != 1) {
    fprintf(stderr, "expected pinned ipv6 allow, got: %s\n", decision.reason);
    return 1;
  }
  if (aegis_policy_engine_check_network_with_ip_ex(&engine,
                                                   &cap_store,
                                                   5201u,
                                                   AEGIS_ACTION_NET_CONNECT,
                                                   "api.safe6.local",
                                                   443,
                                                   AEGIS_NET_PROTO_TCP,
                                                   0u,
                                                   other_v6,
                                                   &decision) != 0) {
    fprintf(stderr, "expected pinned ipv6 mismatch deny\n");
    return 1;
  }
  if (strcmp(decision.reason, "dns rebinding guard blocked host/ip mismatch") != 0) {
    fprintf(stderr, "unexpected dns ipv6 guard reason: %s\n", decision.reason);
    return 1;
  }
  return 0;
}

static int test_dns_dual_stack_strict_mode(void) {
  aegis_capability_store_t cap_store;
  aegis_policy_engine_t engine;
  aegis_sandbox_policy_t policy = {
      5202u, AEGIS_CAP_NET_CLIENT, 0u, 0u, 1u, 0u, 0u};
  aegis_policy_decision_t decision;
  const uint32_t pinned_v4 = 0xC0A80122; /* 192.168.1.34 */
  const char *pinned_v6 = "2001:db8::22";

  aegis_capability_store_init(&cap_store);
  aegis_policy_engine_init(&engine);
  if (aegis_capability_issue(&cap_store, 5202u, AEGIS_CAP_NET_CLIENT) != 0) {
    fprintf(stderr, "dns dual-stack capability issue failed\n");
    return 1;
  }
  if (aegis_policy_engine_set_policy(&engine, &policy) != 0) {
    fprintf(stderr, "dns dual-stack set policy failed\n");
    return 1;
  }
  if (aegis_policy_engine_add_net_rule(
          &engine, 5202u, "api.dual.local", 443, 443, AEGIS_NET_PROTO_TCP, 1u, 0u, 1u) != 0) {
    fprintf(stderr, "dns dual-stack add net rule failed\n");
    return 1;
  }
  if (aegis_policy_engine_pin_dns_ipv4(&engine, 5202u, "api.dual.local", pinned_v4) != 0 ||
      aegis_policy_engine_pin_dns_ipv6(&engine, 5202u, "api.dual.local", pinned_v6) != 0) {
    fprintf(stderr, "dns dual-stack pin failed\n");
    return 1;
  }
  if (aegis_policy_engine_set_dns_dual_stack_strict(&engine, 5202u, "api.dual.local", 1u) != 0) {
    fprintf(stderr, "dns dual-stack strict enable failed\n");
    return 1;
  }
  if (aegis_policy_engine_check_network_with_ip_ex(&engine,
                                                   &cap_store,
                                                   5202u,
                                                   AEGIS_ACTION_NET_CONNECT,
                                                   "api.dual.local",
                                                   443,
                                                   AEGIS_NET_PROTO_TCP,
                                                   pinned_v4,
                                                   0,
                                                   &decision) != 0) {
    fprintf(stderr, "expected strict dual-stack missing family deny\n");
    return 1;
  }
  if (strcmp(decision.reason, "dns dual-stack strict mode requires both ipv4 and ipv6 resolution") != 0) {
    fprintf(stderr, "unexpected strict dual-stack reason: %s\n", decision.reason);
    return 1;
  }
  if (aegis_policy_engine_check_network_with_ip_ex(&engine,
                                                   &cap_store,
                                                   5202u,
                                                   AEGIS_ACTION_NET_CONNECT,
                                                   "api.dual.local",
                                                   443,
                                                   AEGIS_NET_PROTO_TCP,
                                                   pinned_v4,
                                                   pinned_v6,
                                                   &decision) != 1) {
    fprintf(stderr, "expected strict dual-stack allow when both families match\n");
    return 1;
  }
  return 0;
}

static int test_dns_dual_stack_resolution_evidence_trace_json(void) {
  aegis_capability_store_t cap_store;
  aegis_policy_engine_t engine;
  aegis_sandbox_policy_t policy = {
      5203u, AEGIS_CAP_NET_CLIENT, 0u, 0u, 1u, 0u, 0u};
  aegis_policy_decision_t decision;
  const uint32_t pinned_v4 = 0xC0A80123; /* 192.168.1.35 */
  const char *pinned_v6 = "2001:db8::23";
  char json_trace[1024];

  aegis_capability_store_init(&cap_store);
  aegis_policy_engine_init(&engine);
  if (aegis_capability_issue(&cap_store, 5203u, AEGIS_CAP_NET_CLIENT) != 0) {
    fprintf(stderr, "dns evidence capability issue failed\n");
    return 1;
  }
  if (aegis_policy_engine_set_policy(&engine, &policy) != 0) {
    fprintf(stderr, "dns evidence set policy failed\n");
    return 1;
  }
  if (aegis_policy_engine_add_net_rule(
          &engine, 5203u, "api.evidence.local", 443, 443, AEGIS_NET_PROTO_TCP, 1u, 0u, 1u) != 0) {
    fprintf(stderr, "dns evidence add net rule failed\n");
    return 1;
  }
  if (aegis_policy_engine_pin_dns_ipv4(&engine, 5203u, "api.evidence.local", pinned_v4) != 0 ||
      aegis_policy_engine_pin_dns_ipv6(&engine, 5203u, "api.evidence.local", pinned_v6) != 0) {
    fprintf(stderr, "dns evidence pin failed\n");
    return 1;
  }
  if (aegis_policy_engine_set_dns_dual_stack_strict(&engine, 5203u, "api.evidence.local", 1u) != 0) {
    fprintf(stderr, "dns evidence strict enable failed\n");
    return 1;
  }
  if (aegis_policy_engine_check_network_with_ip_trace_json(&engine,
                                                           &cap_store,
                                                           5203u,
                                                           AEGIS_ACTION_NET_CONNECT,
                                                           "api.evidence.local",
                                                           443,
                                                           AEGIS_NET_PROTO_TCP,
                                                           pinned_v4,
                                                           0,
                                                           json_trace,
                                                           sizeof(json_trace),
                                                           &decision) != 0) {
    fprintf(stderr, "expected strict dual-stack missing family deny for evidence trace\n");
    return 1;
  }
  if (strstr(json_trace, "\"dns_resolved_ipv4_present\":1") == 0 ||
      strstr(json_trace, "\"dns_resolved_ipv6_present\":0") == 0 ||
      strstr(json_trace, "\"dns_pin_has_ipv4\":1") == 0 ||
      strstr(json_trace, "\"dns_pin_has_ipv6\":1") == 0 ||
      strstr(json_trace, "\"dns_strict_mode\":1") == 0 ||
      strstr(json_trace, "\"dns_strict_gate_blocked\":1") == 0) {
    fprintf(stderr, "missing dns evidence fields in blocked trace json: %s\n", json_trace);
    return 1;
  }
  if (aegis_policy_engine_check_network_with_ip_trace_json(&engine,
                                                           &cap_store,
                                                           5203u,
                                                           AEGIS_ACTION_NET_CONNECT,
                                                           "api.evidence.local",
                                                           443,
                                                           AEGIS_NET_PROTO_TCP,
                                                           pinned_v4,
                                                           pinned_v6,
                                                           json_trace,
                                                           sizeof(json_trace),
                                                           &decision) != 1) {
    fprintf(stderr, "expected strict dual-stack allow for evidence trace\n");
    return 1;
  }
  if (strstr(json_trace, "\"dns_resolved_ipv4_present\":1") == 0 ||
      strstr(json_trace, "\"dns_resolved_ipv6_present\":1") == 0 ||
      strstr(json_trace, "\"dns_strict_gate_passed\":1") == 0 ||
      strstr(json_trace, "\"decision_allowed\":1") == 0) {
    fprintf(stderr, "missing dns evidence fields in allow trace json: %s\n", json_trace);
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
  aegis_sandbox_policy_t stale = {
      5300u, AEGIS_CAP_FS_READ | AEGIS_CAP_FS_WRITE, 1u, 1u, 0u, 0u, 0u};
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
  stale.policy_revision = 1u;
  if (aegis_policy_engine_hot_reload_policy(&engine, &stale) == 0) {
    fprintf(stderr, "expected stale policy_revision hot reload to fail\n");
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
  if (test_network_scope_debug_trace() != 0) {
    return 1;
  }
  if (test_network_scope_debug_trace_json() != 0) {
    return 1;
  }
  if (test_symlink_scope_resolution() != 0) {
    return 1;
  }
  if (test_filesystem_wildcard_scope() != 0) {
    return 1;
  }
  if (test_filesystem_wildcard_validation_rules() != 0) {
    return 1;
  }
  if (test_filesystem_wildcard_lint_and_compile() != 0) {
    return 1;
  }
  if (test_dns_rebinding_guard() != 0) {
    return 1;
  }
  if (test_dns_rebinding_guard_ipv6() != 0) {
    return 1;
  }
  if (test_dns_dual_stack_strict_mode() != 0) {
    return 1;
  }
  if (test_dns_dual_stack_resolution_evidence_trace_json() != 0) {
    return 1;
  }
  if (test_policy_hot_reload() != 0) {
    return 1;
  }
  puts("sandbox engine tests passed");
  return 0;
}
