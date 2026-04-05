#ifndef AEGIS_SANDBOX_ENGINE_H
#define AEGIS_SANDBOX_ENGINE_H

#include <stddef.h>
#include <stdint.h>

#include "capability.h"
#include "sandbox_policy.h"

#define AEGIS_NETWORK_TRACE_SCHEMA_VERSION 1u
#define AEGIS_NETWORK_TRACE_FORMAT_VERSION 1u

typedef enum {
  AEGIS_ACTION_FS_READ = 1,
  AEGIS_ACTION_FS_WRITE = 2,
  AEGIS_ACTION_NET_CONNECT = 3,
  AEGIS_ACTION_NET_BIND = 4,
  AEGIS_ACTION_DEVICE_IO = 5
} aegis_action_t;

typedef struct {
  uint8_t allowed;
  char reason[96];
} aegis_policy_decision_t;

typedef struct {
  uint64_t total_decisions;
  uint64_t allow_decisions;
  uint64_t deny_decisions;
  uint64_t deny_missing_capability;
  uint64_t deny_policy_gate;
  uint64_t deny_fs_scope;
  uint64_t deny_net_scope;
  uint64_t deny_dns_rebinding;
  uint64_t deny_other;
} aegis_policy_eval_trace_summary_t;

typedef enum {
  AEGIS_FS_SCOPE_DENY = 0,
  AEGIS_FS_SCOPE_READ_ONLY = 1,
  AEGIS_FS_SCOPE_READ_WRITE = 2
} aegis_fs_scope_mode_t;

typedef struct {
  uint32_t process_id;
  char path_prefix[128];
  aegis_fs_scope_mode_t mode;
  uint8_t active;
} aegis_fs_scope_rule_t;

typedef struct {
  uint8_t valid;
  uint8_t has_wildcards;
  uint8_t wildcard_segments;
  char normalized_pattern[128];
  char diagnostic[96];
} aegis_fs_pattern_lint_t;

typedef enum {
  AEGIS_NET_PROTO_TCP = 1,
  AEGIS_NET_PROTO_UDP = 2,
  AEGIS_NET_PROTO_ANY = 255
} aegis_net_protocol_t;

typedef struct {
  uint32_t process_id;
  char host_pattern[96];
  uint16_t port_start;
  uint16_t port_end;
  aegis_net_protocol_t protocol;
  uint8_t allow_connect;
  uint8_t allow_bind;
  uint8_t allow;
  uint8_t active;
} aegis_net_scope_rule_t;

typedef struct {
  uint32_t process_id;
  char host[96];
  uint32_t pinned_ipv4;
  char pinned_ipv6[46];
  uint8_t has_ipv4;
  uint8_t has_ipv6;
  uint8_t strict_dual_stack;
  uint8_t active;
} aegis_dns_pin_rule_t;

typedef struct {
  uint32_t process_id;
  char link_prefix[128];
  char target_prefix[128];
  uint8_t active;
} aegis_symlink_rule_t;

typedef int (*aegis_fs_resolve_path_fn)(const char *path,
                                        char *resolved_path,
                                        size_t resolved_path_size,
                                        void *context);

typedef struct {
  aegis_sandbox_policy_t policies[128];
  uint8_t active[128];
  size_t count;
  aegis_fs_scope_rule_t fs_rules[256];
  aegis_net_scope_rule_t net_rules[256];
  aegis_symlink_rule_t symlink_rules[128];
  aegis_dns_pin_rule_t dns_pin_rules[128];
  aegis_fs_resolve_path_fn fs_resolver;
  void *fs_resolver_context;
} aegis_policy_engine_t;

void aegis_policy_engine_init(aegis_policy_engine_t *engine);
int aegis_policy_engine_set_policy(aegis_policy_engine_t *engine,
                                   const aegis_sandbox_policy_t *policy);
int aegis_policy_engine_hot_reload_policy(aegis_policy_engine_t *engine,
                                          const aegis_sandbox_policy_t *policy);
int aegis_policy_engine_remove_policy(aegis_policy_engine_t *engine, uint32_t process_id);
int aegis_policy_engine_check(const aegis_policy_engine_t *engine,
                              const aegis_capability_store_t *store,
                              uint32_t process_id,
                              aegis_action_t action,
                              aegis_policy_decision_t *decision);
int aegis_policy_engine_add_fs_rule(aegis_policy_engine_t *engine,
                                    uint32_t process_id,
                                    const char *path_prefix,
                                    aegis_fs_scope_mode_t mode);
int aegis_policy_engine_lint_fs_scope_pattern(const char *pattern,
                                              aegis_fs_pattern_lint_t *lint);
int aegis_policy_engine_compile_fs_scope_pattern(const char *pattern,
                                                 char *compiled_pattern,
                                                 size_t compiled_pattern_size,
                                                 char *diagnostic,
                                                 size_t diagnostic_size);
int aegis_policy_engine_clear_fs_rules(aegis_policy_engine_t *engine, uint32_t process_id);
int aegis_policy_engine_check_path(const aegis_policy_engine_t *engine,
                                   const aegis_capability_store_t *store,
                                   uint32_t process_id,
                                   aegis_action_t action,
                                   const char *path,
                                   aegis_policy_decision_t *decision);
int aegis_policy_engine_add_symlink_rule(aegis_policy_engine_t *engine,
                                         uint32_t process_id,
                                         const char *link_prefix,
                                         const char *target_prefix);
int aegis_policy_engine_clear_symlink_rules(aegis_policy_engine_t *engine, uint32_t process_id);
int aegis_policy_engine_set_fs_resolver(aegis_policy_engine_t *engine,
                                        aegis_fs_resolve_path_fn resolver,
                                        void *context);
int aegis_policy_engine_add_net_rule(aegis_policy_engine_t *engine,
                                     uint32_t process_id,
                                     const char *host_pattern,
                                     uint16_t port_start,
                                     uint16_t port_end,
                                     aegis_net_protocol_t protocol,
                                     uint8_t allow_connect,
                                     uint8_t allow_bind,
                                     uint8_t allow);
int aegis_policy_engine_clear_net_rules(aegis_policy_engine_t *engine, uint32_t process_id);
int aegis_policy_engine_check_network(const aegis_policy_engine_t *engine,
                                      const aegis_capability_store_t *store,
                                      uint32_t process_id,
                                      aegis_action_t action,
                                      const char *host,
                                      uint16_t port,
                                      aegis_net_protocol_t protocol,
                                      aegis_policy_decision_t *decision);
int aegis_policy_engine_pin_dns_ipv4(aegis_policy_engine_t *engine, uint32_t process_id,
                                     const char *host, uint32_t ipv4);
int aegis_policy_engine_pin_dns_ipv6(aegis_policy_engine_t *engine, uint32_t process_id,
                                     const char *host, const char *ipv6);
int aegis_policy_engine_set_dns_dual_stack_strict(aegis_policy_engine_t *engine, uint32_t process_id,
                                                   const char *host, uint8_t enabled);
int aegis_policy_engine_clear_dns_pins(aegis_policy_engine_t *engine, uint32_t process_id);
int aegis_policy_engine_check_network_with_ip(const aegis_policy_engine_t *engine,
                                              const aegis_capability_store_t *store,
                                              uint32_t process_id,
                                              aegis_action_t action,
                                              const char *host,
                                              uint16_t port,
                                              aegis_net_protocol_t protocol,
                                              uint32_t resolved_ipv4,
                                              aegis_policy_decision_t *decision);
int aegis_policy_engine_check_network_with_ip_ex(const aegis_policy_engine_t *engine,
                                                 const aegis_capability_store_t *store,
                                                 uint32_t process_id,
                                                 aegis_action_t action,
                                                 const char *host,
                                                 uint16_t port,
                                                 aegis_net_protocol_t protocol,
                                                 uint32_t resolved_ipv4,
                                                 const char *resolved_ipv6,
                                                 aegis_policy_decision_t *decision);
int aegis_policy_engine_check_network_with_ip_trace(const aegis_policy_engine_t *engine,
                                                    const aegis_capability_store_t *store,
                                                    uint32_t process_id,
                                                    aegis_action_t action,
                                                    const char *host,
                                                    uint16_t port,
                                                    aegis_net_protocol_t protocol,
                                                    uint32_t resolved_ipv4,
                                                    const char *resolved_ipv6,
                                                    char *trace,
                                                    size_t trace_size,
                                                    aegis_policy_decision_t *decision);
int aegis_policy_engine_check_network_with_ip_trace_json(const aegis_policy_engine_t *engine,
                                                         const aegis_capability_store_t *store,
                                                         uint32_t process_id,
                                                         aegis_action_t action,
                                                         const char *host,
                                                         uint16_t port,
                                                         aegis_net_protocol_t protocol,
                                                         uint32_t resolved_ipv4,
                                                         const char *resolved_ipv6,
                                                         char *json_trace,
                                                         size_t json_trace_size,
                                                         aegis_policy_decision_t *decision);
void aegis_policy_eval_trace_reset(void);
int aegis_policy_eval_trace_snapshot(aegis_policy_eval_trace_summary_t *summary);
int aegis_policy_eval_trace_summary_json(char *out, size_t out_size);

#endif
