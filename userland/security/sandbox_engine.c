#include "sandbox_engine.h"

#include <stdio.h>
#include <string.h>

static void set_reason(aegis_policy_decision_t *decision, const char *message, uint8_t allowed) {
  if (decision == 0) {
    return;
  }
  decision->allowed = allowed;
  if (message == 0) {
    decision->reason[0] = '\0';
    return;
  }
  snprintf(decision->reason, sizeof(decision->reason), "%s", message);
}

static int find_policy_index(const aegis_policy_engine_t *engine, uint32_t process_id, size_t *index) {
  size_t i;
  if (engine == 0 || index == 0 || process_id == 0) {
    return 0;
  }
  for (i = 0; i < engine->count; ++i) {
    if (engine->active[i] != 0 && engine->policies[i].process_id == process_id) {
      *index = i;
      return 1;
    }
  }
  return 0;
}

static int prefix_matches(const char *path, const char *prefix) {
  size_t prefix_len;
  if (path == 0 || prefix == 0) {
    return 0;
  }
  prefix_len = strlen(prefix);
  if (prefix_len == 0) {
    return 0;
  }
  return strncmp(path, prefix, prefix_len) == 0;
}

static int wildcard_match(const char *pattern, const char *text) {
  if (pattern == 0 || text == 0) {
    return 0;
  }
  if (*pattern == '\0') {
    return *text == '\0';
  }
  if (*pattern == '*') {
    while (*pattern == '*') {
      pattern++;
    }
    if (*pattern == '\0') {
      return 1;
    }
    while (*text != '\0') {
      if (wildcard_match(pattern, text)) {
        return 1;
      }
      text++;
    }
    return wildcard_match(pattern, text);
  }
  if (*text == '\0') {
    return 0;
  }
  if (*pattern == *text) {
    return wildcard_match(pattern + 1, text + 1);
  }
  return 0;
}

static int path_rule_matches(const char *path, const char *rule_pattern) {
  if (strchr(rule_pattern, '*') != 0) {
    return wildcard_match(rule_pattern, path);
  }
  return prefix_matches(path, rule_pattern);
}

static int host_matches(const char *host, const char *pattern) {
  size_t host_len;
  if (host == 0 || pattern == 0 || host[0] == '\0' || pattern[0] == '\0') {
    return 0;
  }
  if (strcmp(pattern, "*") == 0) {
    return 1;
  }
  if (strncmp(pattern, "*.", 2) == 0) {
    const char *suffix = pattern + 1;
    size_t suffix_len = strlen(suffix);
    host_len = strlen(host);
    if (host_len < suffix_len) {
      return 0;
    }
    return strcmp(host + host_len - suffix_len, suffix) == 0;
  }
  return strcmp(host, pattern) == 0;
}

static int host_specificity_score(const char *pattern) {
  size_t len;
  if (pattern == 0 || pattern[0] == '\0') {
    return 0;
  }
  if (strcmp(pattern, "*") == 0) {
    return 1000;
  }
  len = strlen(pattern);
  if (strncmp(pattern, "*.", 2) == 0) {
    return 2000 + (int)len;
  }
  return 3000 + (int)len;
}

static uint32_t action_to_capability(aegis_action_t action, const aegis_sandbox_policy_t *policy,
                                     uint8_t *policy_gate) {
  if (policy_gate != 0) {
    *policy_gate = 0;
  }
  switch (action) {
    case AEGIS_ACTION_FS_READ:
      if (policy_gate != 0) {
        *policy_gate = policy->allow_fs_read;
      }
      return AEGIS_CAP_FS_READ;
    case AEGIS_ACTION_FS_WRITE:
      if (policy_gate != 0) {
        *policy_gate = policy->allow_fs_write;
      }
      return AEGIS_CAP_FS_WRITE;
    case AEGIS_ACTION_NET_CONNECT:
      if (policy_gate != 0) {
        *policy_gate = policy->allow_net_client;
      }
      return AEGIS_CAP_NET_CLIENT;
    case AEGIS_ACTION_NET_BIND:
      if (policy_gate != 0) {
        *policy_gate = policy->allow_net_server;
      }
      return AEGIS_CAP_NET_SERVER;
    case AEGIS_ACTION_DEVICE_IO:
      if (policy_gate != 0) {
        *policy_gate = policy->allow_device_io;
      }
      return AEGIS_CAP_DEVICE_IO;
    default:
      return AEGIS_CAP_NONE;
  }
}

void aegis_policy_engine_init(aegis_policy_engine_t *engine) {
  size_t i;
  if (engine == 0) {
    return;
  }
  engine->count = 0;
  for (i = 0; i < 128; ++i) {
    engine->active[i] = 0;
  }
  for (i = 0; i < 256; ++i) {
    engine->fs_rules[i].active = 0;
    engine->fs_rules[i].process_id = 0;
    engine->fs_rules[i].path_prefix[0] = '\0';
    engine->fs_rules[i].mode = AEGIS_FS_SCOPE_DENY;
  }
  for (i = 0; i < 256; ++i) {
    engine->net_rules[i].active = 0;
    engine->net_rules[i].process_id = 0;
    engine->net_rules[i].host_pattern[0] = '\0';
    engine->net_rules[i].port_start = 0;
    engine->net_rules[i].port_end = 0;
    engine->net_rules[i].protocol = AEGIS_NET_PROTO_ANY;
    engine->net_rules[i].allow_connect = 0;
    engine->net_rules[i].allow_bind = 0;
    engine->net_rules[i].allow = 0;
  }
  for (i = 0; i < 128; ++i) {
    engine->symlink_rules[i].active = 0;
    engine->symlink_rules[i].process_id = 0;
    engine->symlink_rules[i].link_prefix[0] = '\0';
    engine->symlink_rules[i].target_prefix[0] = '\0';
  }
  for (i = 0; i < 128; ++i) {
    engine->dns_pin_rules[i].active = 0;
    engine->dns_pin_rules[i].process_id = 0;
    engine->dns_pin_rules[i].host[0] = '\0';
    engine->dns_pin_rules[i].pinned_ipv4 = 0;
  }
}

int aegis_policy_engine_set_policy(aegis_policy_engine_t *engine,
                                   const aegis_sandbox_policy_t *policy) {
  size_t index = 0;
  char reason[96];
  if (engine == 0 || policy == 0) {
    return -1;
  }
  if (!aegis_sandbox_policy_validate(policy, reason, sizeof(reason))) {
    return -1;
  }
  if (find_policy_index(engine, policy->process_id, &index)) {
    engine->policies[index] = *policy;
    return 0;
  }
  if (engine->count >= 128) {
    return -1;
  }
  engine->policies[engine->count] = *policy;
  engine->active[engine->count] = 1;
  engine->count += 1;
  return 0;
}

int aegis_policy_engine_hot_reload_policy(aegis_policy_engine_t *engine,
                                          const aegis_sandbox_policy_t *policy) {
  aegis_sandbox_policy_t candidate;
  char reason[96];
  size_t index = 0;
  if (engine == 0 || policy == 0) {
    return -1;
  }
  candidate = *policy;
  if (!aegis_sandbox_policy_validate(&candidate, reason, sizeof(reason))) {
    return -1;
  }
  if (find_policy_index(engine, candidate.process_id, &index)) {
    engine->policies[index] = candidate;
    return 0;
  }
  return aegis_policy_engine_set_policy(engine, &candidate);
}

int aegis_policy_engine_remove_policy(aegis_policy_engine_t *engine, uint32_t process_id) {
  size_t index = 0;
  if (!find_policy_index(engine, process_id, &index)) {
    return -1;
  }
  engine->active[index] = 0;
  return 0;
}

int aegis_policy_engine_check(const aegis_policy_engine_t *engine,
                              const aegis_capability_store_t *store,
                              uint32_t process_id,
                              aegis_action_t action,
                              aegis_policy_decision_t *decision) {
  size_t index = 0;
  uint8_t gate = 0;
  uint32_t cap_bit;
  if (decision != 0) {
    decision->allowed = 0;
    decision->reason[0] = '\0';
  }
  if (engine == 0 || store == 0 || process_id == 0 || decision == 0) {
    set_reason(decision, "invalid input", 0);
    return -1;
  }
  if (!find_policy_index(engine, process_id, &index)) {
    set_reason(decision, "no sandbox policy for process", 0);
    return 0;
  }
  cap_bit = action_to_capability(action, &engine->policies[index], &gate);
  if (cap_bit == AEGIS_CAP_NONE) {
    set_reason(decision, "unknown action", 0);
    return 0;
  }
  if (gate == 0) {
    set_reason(decision, "blocked by sandbox policy gate", 0);
    return 0;
  }
  if (!aegis_capability_is_allowed(store, process_id, cap_bit)) {
    set_reason(decision, "missing capability token permission", 0);
    return 0;
  }
  set_reason(decision, "allowed", 1);
  return 1;
}

int aegis_policy_engine_add_fs_rule(aegis_policy_engine_t *engine,
                                    uint32_t process_id,
                                    const char *path_prefix,
                                    aegis_fs_scope_mode_t mode) {
  size_t i;
  size_t free_index = 256;
  if (engine == 0 || process_id == 0 || path_prefix == 0 || path_prefix[0] == '\0') {
    return -1;
  }
  if (mode != AEGIS_FS_SCOPE_DENY && mode != AEGIS_FS_SCOPE_READ_ONLY &&
      mode != AEGIS_FS_SCOPE_READ_WRITE) {
    return -1;
  }
  for (i = 0; i < 256; ++i) {
    if (engine->fs_rules[i].active != 0 &&
        engine->fs_rules[i].process_id == process_id &&
        strcmp(engine->fs_rules[i].path_prefix, path_prefix) == 0) {
      engine->fs_rules[i].mode = mode;
      return 0;
    }
    if (free_index == 256 && engine->fs_rules[i].active == 0) {
      free_index = i;
    }
  }
  if (free_index == 256) {
    return -1;
  }
  engine->fs_rules[free_index].active = 1;
  engine->fs_rules[free_index].process_id = process_id;
  snprintf(engine->fs_rules[free_index].path_prefix,
           sizeof(engine->fs_rules[free_index].path_prefix),
           "%s",
           path_prefix);
  engine->fs_rules[free_index].mode = mode;
  return 0;
}

int aegis_policy_engine_clear_fs_rules(aegis_policy_engine_t *engine, uint32_t process_id) {
  size_t i;
  int removed = 0;
  if (engine == 0 || process_id == 0) {
    return -1;
  }
  for (i = 0; i < 256; ++i) {
    if (engine->fs_rules[i].active != 0 && engine->fs_rules[i].process_id == process_id) {
      engine->fs_rules[i].active = 0;
      engine->fs_rules[i].process_id = 0;
      engine->fs_rules[i].path_prefix[0] = '\0';
      engine->fs_rules[i].mode = AEGIS_FS_SCOPE_DENY;
      removed = 1;
    }
  }
  return removed ? 0 : -1;
}

int aegis_policy_engine_check_path(const aegis_policy_engine_t *engine,
                                   const aegis_capability_store_t *store,
                                   uint32_t process_id,
                                   aegis_action_t action,
                                   const char *path,
                                   aegis_policy_decision_t *decision) {
  int base_rc;
  size_t i;
  size_t longest = 0;
  aegis_fs_scope_mode_t best_mode = AEGIS_FS_SCOPE_DENY;
  int found = 0;
  char resolved_path[256];

  base_rc = aegis_policy_engine_check(engine, store, process_id, action, decision);
  if (base_rc != 1) {
    return base_rc;
  }
  if (action != AEGIS_ACTION_FS_READ && action != AEGIS_ACTION_FS_WRITE) {
    return 1;
  }
  if (path == 0 || path[0] == '\0') {
    set_reason(decision, "filesystem path is required", 0);
    return 0;
  }
  snprintf(resolved_path, sizeof(resolved_path), "%s", path);

  for (i = 0; i < 8; ++i) {
    size_t j;
    int changed = 0;
    for (j = 0; j < 128; ++j) {
      const aegis_symlink_rule_t *rule = &engine->symlink_rules[j];
      char tmp[256];
      size_t link_len;
      if (rule->active == 0 || rule->process_id != process_id) {
        continue;
      }
      if (!prefix_matches(resolved_path, rule->link_prefix)) {
        continue;
      }
      link_len = strlen(rule->link_prefix);
      snprintf(tmp, sizeof(tmp), "%s%s", rule->target_prefix, resolved_path + link_len);
      snprintf(resolved_path, sizeof(resolved_path), "%s", tmp);
      changed = 1;
      break;
    }
    if (!changed) {
      break;
    }
    if (i == 7) {
      set_reason(decision, "symlink resolution depth exceeded", 0);
      return 0;
    }
  }

  for (i = 0; i < 256; ++i) {
    size_t len;
    if (engine->fs_rules[i].active == 0 || engine->fs_rules[i].process_id != process_id) {
      continue;
    }
    if (!path_rule_matches(resolved_path, engine->fs_rules[i].path_prefix)) {
      continue;
    }
    if (engine->fs_rules[i].mode == AEGIS_FS_SCOPE_DENY) {
      set_reason(decision, "denied by filesystem scope rule", 0);
      return 0;
    }
    len = strlen(engine->fs_rules[i].path_prefix);
    if (!found || len > longest) {
      found = 1;
      longest = len;
      best_mode = engine->fs_rules[i].mode;
    }
  }

  if (!found) {
    set_reason(decision, "no matching filesystem scope rule", 0);
    return 0;
  }
  if (action == AEGIS_ACTION_FS_WRITE && best_mode != AEGIS_FS_SCOPE_READ_WRITE) {
    set_reason(decision, "write blocked by read-only filesystem scope", 0);
    return 0;
  }
  set_reason(decision, "allowed by filesystem scope", 1);
  return 1;
}

int aegis_policy_engine_add_symlink_rule(aegis_policy_engine_t *engine,
                                         uint32_t process_id,
                                         const char *link_prefix,
                                         const char *target_prefix) {
  size_t i;
  size_t free_index = 128;
  if (engine == 0 || process_id == 0 || link_prefix == 0 || target_prefix == 0 ||
      link_prefix[0] == '\0' || target_prefix[0] == '\0') {
    return -1;
  }
  for (i = 0; i < 128; ++i) {
    if (engine->symlink_rules[i].active != 0 &&
        engine->symlink_rules[i].process_id == process_id &&
        strcmp(engine->symlink_rules[i].link_prefix, link_prefix) == 0) {
      snprintf(engine->symlink_rules[i].target_prefix,
               sizeof(engine->symlink_rules[i].target_prefix),
               "%s",
               target_prefix);
      return 0;
    }
    if (free_index == 128 && engine->symlink_rules[i].active == 0) {
      free_index = i;
    }
  }
  if (free_index == 128) {
    return -1;
  }
  engine->symlink_rules[free_index].active = 1;
  engine->symlink_rules[free_index].process_id = process_id;
  snprintf(engine->symlink_rules[free_index].link_prefix,
           sizeof(engine->symlink_rules[free_index].link_prefix),
           "%s",
           link_prefix);
  snprintf(engine->symlink_rules[free_index].target_prefix,
           sizeof(engine->symlink_rules[free_index].target_prefix),
           "%s",
           target_prefix);
  return 0;
}

int aegis_policy_engine_clear_symlink_rules(aegis_policy_engine_t *engine, uint32_t process_id) {
  size_t i;
  int removed = 0;
  if (engine == 0 || process_id == 0) {
    return -1;
  }
  for (i = 0; i < 128; ++i) {
    if (engine->symlink_rules[i].active != 0 && engine->symlink_rules[i].process_id == process_id) {
      engine->symlink_rules[i].active = 0;
      engine->symlink_rules[i].process_id = 0;
      engine->symlink_rules[i].link_prefix[0] = '\0';
      engine->symlink_rules[i].target_prefix[0] = '\0';
      removed = 1;
    }
  }
  return removed ? 0 : -1;
}

int aegis_policy_engine_add_net_rule(aegis_policy_engine_t *engine,
                                     uint32_t process_id,
                                     const char *host_pattern,
                                     uint16_t port_start,
                                     uint16_t port_end,
                                     aegis_net_protocol_t protocol,
                                     uint8_t allow_connect,
                                     uint8_t allow_bind,
                                     uint8_t allow) {
  size_t i;
  size_t free_index = 256;
  if (engine == 0 || process_id == 0 || host_pattern == 0 || host_pattern[0] == '\0') {
    return -1;
  }
  if (port_start == 0 || port_end == 0 || port_start > port_end) {
    return -1;
  }
  if (protocol != AEGIS_NET_PROTO_TCP && protocol != AEGIS_NET_PROTO_UDP &&
      protocol != AEGIS_NET_PROTO_ANY) {
    return -1;
  }
  if (allow_connect == 0 && allow_bind == 0) {
    return -1;
  }
  for (i = 0; i < 256; ++i) {
    if (engine->net_rules[i].active != 0 &&
        engine->net_rules[i].process_id == process_id &&
        strcmp(engine->net_rules[i].host_pattern, host_pattern) == 0 &&
        engine->net_rules[i].port_start == port_start &&
        engine->net_rules[i].port_end == port_end &&
        engine->net_rules[i].protocol == protocol &&
        engine->net_rules[i].allow_connect == allow_connect &&
        engine->net_rules[i].allow_bind == allow_bind) {
      engine->net_rules[i].allow = allow != 0 ? 1 : 0;
      return 0;
    }
    if (free_index == 256 && engine->net_rules[i].active == 0) {
      free_index = i;
    }
  }
  if (free_index == 256) {
    return -1;
  }
  engine->net_rules[free_index].active = 1;
  engine->net_rules[free_index].process_id = process_id;
  snprintf(engine->net_rules[free_index].host_pattern,
           sizeof(engine->net_rules[free_index].host_pattern),
           "%s",
           host_pattern);
  engine->net_rules[free_index].port_start = port_start;
  engine->net_rules[free_index].port_end = port_end;
  engine->net_rules[free_index].protocol = protocol;
  engine->net_rules[free_index].allow_connect = allow_connect != 0 ? 1 : 0;
  engine->net_rules[free_index].allow_bind = allow_bind != 0 ? 1 : 0;
  engine->net_rules[free_index].allow = allow != 0 ? 1 : 0;
  return 0;
}

int aegis_policy_engine_clear_net_rules(aegis_policy_engine_t *engine, uint32_t process_id) {
  size_t i;
  int removed = 0;
  if (engine == 0 || process_id == 0) {
    return -1;
  }
  for (i = 0; i < 256; ++i) {
    if (engine->net_rules[i].active != 0 && engine->net_rules[i].process_id == process_id) {
      engine->net_rules[i].active = 0;
      engine->net_rules[i].process_id = 0;
      engine->net_rules[i].host_pattern[0] = '\0';
      engine->net_rules[i].port_start = 0;
      engine->net_rules[i].port_end = 0;
      engine->net_rules[i].protocol = AEGIS_NET_PROTO_ANY;
      engine->net_rules[i].allow_connect = 0;
      engine->net_rules[i].allow_bind = 0;
      engine->net_rules[i].allow = 0;
      removed = 1;
    }
  }
  return removed ? 0 : -1;
}

int aegis_policy_engine_check_network(const aegis_policy_engine_t *engine,
                                      const aegis_capability_store_t *store,
                                      uint32_t process_id,
                                      aegis_action_t action,
                                      const char *host,
                                      uint16_t port,
                                      aegis_net_protocol_t protocol,
                                      aegis_policy_decision_t *decision) {
  return aegis_policy_engine_check_network_with_ip(engine, store, process_id, action, host, port,
                                                   protocol, 0u, decision);
}

int aegis_policy_engine_pin_dns_ipv4(aegis_policy_engine_t *engine, uint32_t process_id,
                                     const char *host, uint32_t ipv4) {
  size_t i;
  size_t free_index = 128;
  if (engine == 0 || process_id == 0 || host == 0 || host[0] == '\0' || ipv4 == 0u) {
    return -1;
  }
  for (i = 0; i < 128; ++i) {
    if (engine->dns_pin_rules[i].active != 0 &&
        engine->dns_pin_rules[i].process_id == process_id &&
        strcmp(engine->dns_pin_rules[i].host, host) == 0) {
      engine->dns_pin_rules[i].pinned_ipv4 = ipv4;
      return 0;
    }
    if (free_index == 128 && engine->dns_pin_rules[i].active == 0) {
      free_index = i;
    }
  }
  if (free_index == 128) {
    return -1;
  }
  engine->dns_pin_rules[free_index].active = 1;
  engine->dns_pin_rules[free_index].process_id = process_id;
  engine->dns_pin_rules[free_index].pinned_ipv4 = ipv4;
  snprintf(engine->dns_pin_rules[free_index].host,
           sizeof(engine->dns_pin_rules[free_index].host),
           "%s",
           host);
  return 0;
}

int aegis_policy_engine_clear_dns_pins(aegis_policy_engine_t *engine, uint32_t process_id) {
  size_t i;
  int removed = 0;
  if (engine == 0 || process_id == 0) {
    return -1;
  }
  for (i = 0; i < 128; ++i) {
    if (engine->dns_pin_rules[i].active != 0 && engine->dns_pin_rules[i].process_id == process_id) {
      engine->dns_pin_rules[i].active = 0;
      engine->dns_pin_rules[i].process_id = 0;
      engine->dns_pin_rules[i].host[0] = '\0';
      engine->dns_pin_rules[i].pinned_ipv4 = 0;
      removed = 1;
    }
  }
  return removed ? 0 : -1;
}

int aegis_policy_engine_check_network_with_ip(const aegis_policy_engine_t *engine,
                                              const aegis_capability_store_t *store,
                                              uint32_t process_id,
                                              aegis_action_t action,
                                              const char *host,
                                              uint16_t port,
                                              aegis_net_protocol_t protocol,
                                              uint32_t resolved_ipv4,
                                              aegis_policy_decision_t *decision) {
  int base_rc;
  size_t i;
  int best_score = -1;
  int best_allow = 0;
  if (action != AEGIS_ACTION_NET_CONNECT && action != AEGIS_ACTION_NET_BIND) {
    set_reason(decision, "network check requires net action", 0);
    return 0;
  }
  base_rc = aegis_policy_engine_check(engine, store, process_id, action, decision);
  if (base_rc != 1) {
    return base_rc;
  }
  if (host == 0 || host[0] == '\0' || port == 0) {
    set_reason(decision, "network host/port required", 0);
    return 0;
  }
  if (protocol != AEGIS_NET_PROTO_TCP && protocol != AEGIS_NET_PROTO_UDP) {
    set_reason(decision, "unsupported network protocol", 0);
    return 0;
  }
  if (resolved_ipv4 != 0u) {
    for (i = 0; i < 128; ++i) {
      const aegis_dns_pin_rule_t *pin = &engine->dns_pin_rules[i];
      if (pin->active == 0 || pin->process_id != process_id) {
        continue;
      }
      if (strcmp(pin->host, host) != 0) {
        continue;
      }
      if (pin->pinned_ipv4 != resolved_ipv4) {
        set_reason(decision, "dns rebinding guard blocked host/ip mismatch", 0);
        return 0;
      }
    }
  }
  for (i = 0; i < 256; ++i) {
    const aegis_net_scope_rule_t *rule = &engine->net_rules[i];
    uint8_t action_match = 0;
    int score = 0;
    uint16_t range = 0;
    if (rule->active == 0 || rule->process_id != process_id) {
      continue;
    }
    if (!host_matches(host, rule->host_pattern)) {
      continue;
    }
    if (port < rule->port_start || port > rule->port_end) {
      continue;
    }
    if (rule->protocol != AEGIS_NET_PROTO_ANY && rule->protocol != protocol) {
      continue;
    }
    if (action == AEGIS_ACTION_NET_CONNECT && rule->allow_connect != 0) {
      action_match = 1;
    }
    if (action == AEGIS_ACTION_NET_BIND && rule->allow_bind != 0) {
      action_match = 1;
    }
    if (action_match == 0) {
      continue;
    }
    range = (uint16_t)(rule->port_end - rule->port_start);
    score += host_specificity_score(rule->host_pattern);
    score += (rule->protocol == AEGIS_NET_PROTO_ANY) ? 0 : 100;
    score += 65535 - (int)range;
    if (score > best_score) {
      best_score = score;
      best_allow = rule->allow != 0 ? 1 : 0;
    } else if (score == best_score && rule->allow == 0) {
      /* deterministic safety tie-break: deny wins at equal specificity */
      best_allow = 0;
    }
  }
  if (best_score < 0) {
    set_reason(decision, "no matching network scope rule", 0);
    return 0;
  }
  if (!best_allow) {
    set_reason(decision, "denied by network scope rule", 0);
    return 0;
  }
  set_reason(decision, "allowed by network scope", 1);
  return 1;
}
