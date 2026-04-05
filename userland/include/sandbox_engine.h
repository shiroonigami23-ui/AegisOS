#ifndef AEGIS_SANDBOX_ENGINE_H
#define AEGIS_SANDBOX_ENGINE_H

#include <stddef.h>
#include <stdint.h>

#include "capability.h"
#include "sandbox_policy.h"

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
  uint8_t active;
} aegis_dns_pin_rule_t;

typedef struct {
  uint32_t process_id;
  char link_prefix[128];
  char target_prefix[128];
  uint8_t active;
} aegis_symlink_rule_t;

typedef struct {
  aegis_sandbox_policy_t policies[128];
  uint8_t active[128];
  size_t count;
  aegis_fs_scope_rule_t fs_rules[256];
  aegis_net_scope_rule_t net_rules[256];
  aegis_symlink_rule_t symlink_rules[128];
  aegis_dns_pin_rule_t dns_pin_rules[128];
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

#endif
