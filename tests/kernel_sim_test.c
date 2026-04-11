#include <stdio.h>
#include <string.h>
#include "kernel.h"

static int test_kernel_boot(void) {
  if (aegis_kernel_boot_check() != 0) {
    fprintf(stderr, "kernel boot check failed\n");
    return 1;
  }
  return 0;
}

static int test_vm_region_map_abstraction(void) {
  aegis_vm_space_t space;
  aegis_vm_region_t region;
  char summary[1024];
  char tiny[24];
  aegis_vm_space_init(&space);
  if (aegis_vm_map(&space, 0x1000u, 0x2000u, 0x3u) != 0) {
    fprintf(stderr, "vm map initial region failed\n");
    return 1;
  }
  if (aegis_vm_map(&space, 0x2800u, 0x1000u, 0x1u) == 0) {
    fprintf(stderr, "vm map overlap should fail\n");
    return 1;
  }
  if (aegis_vm_map(&space, 0x4000u, 0x1000u, 0x1u) != 0) {
    fprintf(stderr, "vm map adjacent region failed\n");
    return 1;
  }
  if (space.count != 2u) {
    fprintf(stderr, "vm map expected count 2\n");
    return 1;
  }
  if (aegis_vm_query(&space, 0x1100u, &region) != 0 || region.base != 0x1000u || region.size != 0x2000u) {
    fprintf(stderr, "vm query region lookup failed\n");
    return 1;
  }
  if (aegis_vm_query(&space, 0x9000u, &region) == 0) {
    fprintf(stderr, "vm query expected miss for unmapped address\n");
    return 1;
  }
  if (aegis_vm_unmap(&space, 0x1000u, 0x2000u) != 0 || space.count != 1u) {
    fprintf(stderr, "vm unmap expected success and count decrement\n");
    return 1;
  }
  if (aegis_vm_summary_json(&space, summary, sizeof(summary)) <= 0) {
    fprintf(stderr, "vm summary json generation failed\n");
    return 1;
  }
  if (strstr(summary, "\"schema_version\":1") == 0 ||
      strstr(summary, "\"region_count\":1") == 0 ||
      strstr(summary, "\"base\":16384") == 0) {
    fprintf(stderr, "vm summary json missing expected fields: %s\n", summary);
    return 1;
  }
  if (aegis_vm_summary_json(&space, tiny, sizeof(tiny)) >= 0) {
    fprintf(stderr, "vm summary json expected tiny buffer failure\n");
    return 1;
  }
  return 0;
}

static int test_vm_region_split_and_permission_update(void) {
  aegis_vm_space_t space;
  aegis_vm_region_t region;
  char summary[1024];
  aegis_vm_space_init(&space);
  if (aegis_vm_map(&space, 0x8000u, 0x2000u, 0x1u) != 0) {
    fprintf(stderr, "vm split setup map failed\n");
    return 1;
  }
  if (aegis_vm_split_region(&space, 0x8000u, 0x2000u, 0x1000u) != 0) {
    fprintf(stderr, "vm split expected success\n");
    return 1;
  }
  if (space.count != 2u) {
    fprintf(stderr, "vm split expected region count 2\n");
    return 1;
  }
  if (aegis_vm_update_flags(&space, 0x9000u, 0x1000u, 0x7u) != 0) {
    fprintf(stderr, "vm update flags expected success\n");
    return 1;
  }
  if (aegis_vm_query(&space, 0x9001u, &region) != 0 || region.flags != 0x7u) {
    fprintf(stderr, "vm query after flag update failed\n");
    return 1;
  }
  if (aegis_vm_split_region(&space, 0x8000u, 0x1000u, 0x1000u) == 0) {
    fprintf(stderr, "vm split with boundary offset should fail\n");
    return 1;
  }
  if (aegis_vm_update_flags(&space, 0x8000u, 0x2222u, 0x2u) == 0) {
    fprintf(stderr, "vm update flags on unknown exact region should fail\n");
    return 1;
  }
  if (aegis_vm_summary_json(&space, summary, sizeof(summary)) <= 0) {
    fprintf(stderr, "vm split summary generation failed\n");
    return 1;
  }
  if (strstr(summary, "\"region_count\":2") == 0 || strstr(summary, "\"flags\":7") == 0) {
    fprintf(stderr, "vm split summary missing expected fields: %s\n", summary);
    return 1;
  }
  return 0;
}

static int test_ipc_envelope_format_helpers(void) {
  aegis_ipc_envelope_t in = {AEGIS_IPC_ENVELOPE_SCHEMA_VERSION, 7u, 0xA5u, 512u, 42u};
  aegis_ipc_envelope_t out;
  uint8_t buf[16];
  uint8_t tiny[8];
  if (aegis_ipc_envelope_validate(&in, 4096u) != 0) {
    fprintf(stderr, "ipc validate expected success\n");
    return 1;
  }
  if (aegis_ipc_envelope_encode(&in, buf, sizeof(buf)) != 16) {
    fprintf(stderr, "ipc encode expected fixed header size\n");
    return 1;
  }
  if (aegis_ipc_envelope_decode(buf, sizeof(buf), &out) != 0) {
    fprintf(stderr, "ipc decode failed\n");
    return 1;
  }
  if (out.schema_version != in.schema_version || out.message_type != in.message_type ||
      out.flags != in.flags || out.payload_size != in.payload_size ||
      out.correlation_id != in.correlation_id) {
    fprintf(stderr, "ipc roundtrip mismatch\n");
    return 1;
  }
  out.schema_version = 99u;
  if (aegis_ipc_envelope_validate(&out, 4096u) == 0) {
    fprintf(stderr, "ipc validate expected schema mismatch failure\n");
    return 1;
  }
  out = in;
  out.payload_size = 9999u;
  if (aegis_ipc_envelope_validate(&out, 4096u) == 0) {
    fprintf(stderr, "ipc validate expected payload bound failure\n");
    return 1;
  }
  if (aegis_ipc_envelope_encode(&in, tiny, sizeof(tiny)) >= 0) {
    fprintf(stderr, "ipc encode expected tiny buffer failure\n");
    return 1;
  }
  if (aegis_ipc_envelope_decode(buf, sizeof(tiny), &out) >= 0) {
    fprintf(stderr, "ipc decode expected short buffer failure\n");
    return 1;
  }
  return 0;
}

static int test_ipc_payload_guard_helper(void) {
  aegis_ipc_envelope_t env = {AEGIS_IPC_ENVELOPE_SCHEMA_VERSION, 9u, 0u, 100u, 500u};
  uint32_t remaining = 0u;
  if (aegis_ipc_envelope_payload_fits(&env, 200u, &remaining) != 1 || remaining != 84u) {
    fprintf(stderr, "ipc payload guard expected fit with remaining bytes\n");
    return 1;
  }
  if (aegis_ipc_envelope_payload_fits(&env, 100u, &remaining) != 0 || remaining != 0u) {
    fprintf(stderr, "ipc payload guard expected overflow reject\n");
    return 1;
  }
  env.payload_size = UINT32_MAX;
  if (aegis_ipc_envelope_payload_fits(&env, UINT32_MAX, &remaining) >= 0) {
    fprintf(stderr, "ipc payload guard expected arithmetic overflow fail\n");
    return 1;
  }
  if (aegis_ipc_envelope_payload_fits(0, 200u, &remaining) >= 0) {
    fprintf(stderr, "ipc payload guard expected null input failure\n");
    return 1;
  }
  return 0;
}

static int test_scheduler_round_robin(void) {
  aegis_scheduler_t scheduler;
  uint32_t pid = 0;
  aegis_scheduler_init(&scheduler);

  if (aegis_scheduler_add(&scheduler, 1001u) != 0 ||
      aegis_scheduler_add(&scheduler, 1002u) != 0 ||
      aegis_scheduler_add(&scheduler, 1003u) != 0) {
    fprintf(stderr, "scheduler add failed\n");
    return 1;
  }
  if (aegis_scheduler_count(&scheduler) != 3u) {
    fprintf(stderr, "scheduler count mismatch\n");
    return 1;
  }
  if (aegis_scheduler_next(&scheduler, &pid) != 0 || pid != 1001u) {
    fprintf(stderr, "expected pid 1001\n");
    return 1;
  }
  if (aegis_scheduler_next(&scheduler, &pid) != 0 || pid != 1002u) {
    fprintf(stderr, "expected pid 1002\n");
    return 1;
  }
  if (aegis_scheduler_next(&scheduler, &pid) != 0 || pid != 1003u) {
    fprintf(stderr, "expected pid 1003\n");
    return 1;
  }
  if (aegis_scheduler_next(&scheduler, &pid) != 0 || pid != 1001u) {
    fprintf(stderr, "expected pid 1001 after wrap\n");
    return 1;
  }
  return 0;
}

static int test_scheduler_priority_weighting(void) {
  aegis_scheduler_t scheduler;
  uint32_t pid = 0;
  int high_count = 0;
  int low_count = 0;
  int i;
  aegis_scheduler_init(&scheduler);
  if (aegis_scheduler_add_with_priority(&scheduler, 11u, AEGIS_PRIORITY_HIGH) != 0 ||
      aegis_scheduler_add_with_priority(&scheduler, 22u, AEGIS_PRIORITY_LOW) != 0) {
    fprintf(stderr, "priority scheduler add failed\n");
    return 1;
  }
  for (i = 0; i < 8; ++i) {
    if (aegis_scheduler_next(&scheduler, &pid) != 0) {
      fprintf(stderr, "priority scheduler next failed\n");
      return 1;
    }
    if (pid == 11u) {
      high_count += 1;
    } else if (pid == 22u) {
      low_count += 1;
    }
  }
  if (high_count <= low_count) {
    fprintf(stderr, "expected high priority process to run more often\n");
    return 1;
  }
  if (aegis_scheduler_set_priority(&scheduler, 22u, AEGIS_PRIORITY_HIGH) != 0) {
    fprintf(stderr, "set priority failed\n");
    return 1;
  }
  return 0;
}

static int test_scheduler_aging_boost_fairness(void) {
  aegis_scheduler_t scheduler;
  uint32_t pid = 0;
  uint8_t switched = 0;
  uint32_t high_a = 0;
  uint32_t high_b = 0;
  uint32_t low = 0;
  int i;
  aegis_scheduler_init(&scheduler);
  aegis_scheduler_set_quantum(&scheduler, 1u);
  if (aegis_scheduler_add_with_priority(&scheduler, 1201u, AEGIS_PRIORITY_HIGH) != 0 ||
      aegis_scheduler_add_with_priority(&scheduler, 1202u, AEGIS_PRIORITY_HIGH) != 0 ||
      aegis_scheduler_add_with_priority(&scheduler, 1203u, AEGIS_PRIORITY_LOW) != 0) {
    fprintf(stderr, "aging fairness add failed\n");
    return 1;
  }
  for (i = 0; i < 70; ++i) {
    if (aegis_scheduler_on_tick(&scheduler, &pid, &switched) != 0) {
      fprintf(stderr, "aging fairness tick failed\n");
      return 1;
    }
  }
  if (aegis_scheduler_dispatch_count_for(&scheduler, 1201u, &high_a) != 0 ||
      aegis_scheduler_dispatch_count_for(&scheduler, 1202u, &high_b) != 0 ||
      aegis_scheduler_dispatch_count_for(&scheduler, 1203u, &low) != 0) {
    fprintf(stderr, "aging fairness dispatch counts failed\n");
    return 1;
  }
  if (low < 13u) {
    fprintf(stderr, "aging fairness expected low-priority boost, got low dispatches=%u\n", low);
    return 1;
  }
  if (high_a <= low || high_b <= low) {
    fprintf(stderr, "aging fairness should still keep high priorities ahead (%u,%u vs %u)\n",
            high_a,
            high_b,
            low);
    return 1;
  }
  return 0;
}

static int test_scheduler_admission_limits_and_snapshot(void) {
  aegis_scheduler_t scheduler;
  uint8_t limit = 0u;
  uint64_t drops = 0u;
  char json[512];
  aegis_scheduler_init(&scheduler);
  if (aegis_scheduler_set_admission_limit(&scheduler, AEGIS_PRIORITY_HIGH, 1u) != 0 ||
      aegis_scheduler_set_admission_limit(&scheduler, AEGIS_PRIORITY_NORMAL, 2u) != 0 ||
      aegis_scheduler_set_admission_limit(&scheduler, AEGIS_PRIORITY_LOW, 1u) != 0) {
    fprintf(stderr, "admission limit setup failed\n");
    return 1;
  }
  if (aegis_scheduler_add_with_priority(&scheduler, 101u, AEGIS_PRIORITY_HIGH) != 0) {
    fprintf(stderr, "expected first high-priority admission\n");
    return 1;
  }
  if (aegis_scheduler_add_with_priority(&scheduler, 102u, AEGIS_PRIORITY_HIGH) == 0) {
    fprintf(stderr, "expected second high-priority admission to be rejected\n");
    return 1;
  }
  if (aegis_scheduler_add_with_priority(&scheduler, 201u, AEGIS_PRIORITY_NORMAL) != 0 ||
      aegis_scheduler_add_with_priority(&scheduler, 202u, AEGIS_PRIORITY_NORMAL) != 0 ||
      aegis_scheduler_add_with_priority(&scheduler, 203u, AEGIS_PRIORITY_NORMAL) == 0) {
    fprintf(stderr, "normal-priority admission limit behavior mismatch\n");
    return 1;
  }
  if (aegis_scheduler_get_admission_limit(&scheduler, AEGIS_PRIORITY_HIGH, &limit) != 0 || limit != 1u) {
    fprintf(stderr, "admission limit getter mismatch for high priority\n");
    return 1;
  }
  if (aegis_scheduler_admission_drop_count(&scheduler, AEGIS_PRIORITY_HIGH, &drops) != 0 || drops != 1u) {
    fprintf(stderr, "high-priority admission drop counter mismatch\n");
    return 1;
  }
  if (aegis_scheduler_admission_drop_count(&scheduler, AEGIS_PRIORITY_NORMAL, &drops) != 0 ||
      drops != 1u) {
    fprintf(stderr, "normal-priority admission drop counter mismatch\n");
    return 1;
  }
  if (aegis_scheduler_admission_snapshot_json(&scheduler, json, sizeof(json)) <= 0) {
    fprintf(stderr, "admission snapshot json failed\n");
    return 1;
  }
  if (strstr(json, "\"schema_version\":1") == 0 ||
      strstr(json, "\"limits\":{\"high\":1,\"normal\":2,\"low\":1}") == 0 ||
      strstr(json, "\"counts\":{\"high\":1,\"normal\":2,\"low\":0}") == 0 ||
      strstr(json, "\"drops\":{\"high\":1,\"normal\":1,\"low\":0}") == 0) {
    fprintf(stderr, "admission snapshot json missing expected fields: %s\n", json);
    return 1;
  }
  return 0;
}

static int test_scheduler_admission_profile_presets(void) {
  aegis_scheduler_t scheduler;
  uint8_t profile = 0u;
  char json[512];
  aegis_scheduler_init(&scheduler);
  if (aegis_scheduler_apply_admission_profile(&scheduler, AEGIS_SCHED_ADMISSION_PROFILE_MINIMAL) != 0) {
    fprintf(stderr, "failed to apply minimal admission profile\n");
    return 1;
  }
  if (aegis_scheduler_get_admission_limit(&scheduler, AEGIS_PRIORITY_NORMAL, &profile) != 0 ||
      profile != 8u) {
    fprintf(stderr, "minimal profile normal limit mismatch\n");
    return 1;
  }
  if (aegis_scheduler_current_admission_profile(&scheduler, &profile) != 0 ||
      profile != AEGIS_SCHED_ADMISSION_PROFILE_MINIMAL) {
    fprintf(stderr, "minimal profile id mismatch\n");
    return 1;
  }
  if (aegis_scheduler_apply_admission_profile(&scheduler, AEGIS_SCHED_ADMISSION_PROFILE_SERVER) != 0) {
    fprintf(stderr, "failed to apply server admission profile\n");
    return 1;
  }
  if (aegis_scheduler_get_admission_limit(&scheduler, AEGIS_PRIORITY_HIGH, &profile) != 0 ||
      profile != 12u) {
    fprintf(stderr, "server profile high limit mismatch\n");
    return 1;
  }
  if (aegis_scheduler_admission_snapshot_json(&scheduler, json, sizeof(json)) <= 0 ||
      strstr(json, "\"profile_id\":3") == 0 ||
      strstr(json, "\"limits\":{\"high\":12,\"normal\":36,\"low\":16}") == 0) {
    fprintf(stderr, "server profile snapshot mismatch: %s\n", json);
    return 1;
  }
  return 0;
}

static int test_scheduler_admission_profile_name_resolver(void) {
  aegis_scheduler_t scheduler;
  uint8_t profile = 0u;
  aegis_scheduler_init(&scheduler);
  if (aegis_scheduler_apply_admission_profile_name(&scheduler, "desktop") != 0) {
    fprintf(stderr, "profile name desktop should apply\n");
    return 1;
  }
  if (aegis_scheduler_current_admission_profile(&scheduler, &profile) != 0 ||
      profile != AEGIS_SCHED_ADMISSION_PROFILE_DESKTOP) {
    fprintf(stderr, "profile name desktop id mismatch\n");
    return 1;
  }
  if (aegis_scheduler_apply_admission_profile_name(&scheduler, "unknown") == 0) {
    fprintf(stderr, "unknown profile name should fail\n");
    return 1;
  }
  return 0;
}

static int test_namespace_isolation_simulator(void) {
  aegis_namespace_table_t table;
  uint32_t ns_a = 0u;
  uint32_t ns_b = 0u;
  uint32_t local_a = 0u;
  uint32_t local_b = 0u;
  uint32_t global = 0u;
  uint32_t local_roundtrip = 0u;
  uint8_t allowed = 0u;
  char json[2048];
  char tiny[32];
  aegis_namespace_table_init(&table);
  if (aegis_namespace_create(&table, 1u, &ns_a) != 0 ||
      aegis_namespace_create(&table, 1u, &ns_b) != 0) {
    fprintf(stderr, "namespace create failed\n");
    return 1;
  }
  if (aegis_namespace_attach_process(&table, 6001u, ns_a, &local_a) != 0 ||
      aegis_namespace_attach_process(&table, 6002u, ns_b, &local_b) != 0) {
    fprintf(stderr, "namespace attach process failed\n");
    return 1;
  }
  if (local_a != 101u || local_b != 101u) {
    fprintf(stderr, "expected local pid spaces to be isolated\n");
    return 1;
  }
  if (aegis_namespace_translate_local_to_global(&table, ns_a, local_a, &global) != 0 ||
      global != 6001u) {
    fprintf(stderr, "local->global translation failed\n");
    return 1;
  }
  if (aegis_namespace_translate_global_to_local(&table, ns_b, 6002u, &local_roundtrip) != 0 ||
      local_roundtrip != local_b) {
    fprintf(stderr, "global->local translation failed\n");
    return 1;
  }
  if (aegis_namespace_can_inspect(&table, 6001u, 6002u, &allowed) != 0 || allowed != 0u) {
    fprintf(stderr, "cross-namespace inspect should be denied\n");
    return 1;
  }
  if (aegis_namespace_can_inspect(&table, 6001u, 6001u, &allowed) != 0 || allowed != 1u) {
    fprintf(stderr, "same-process inspect should be allowed\n");
    return 1;
  }
  if (aegis_namespace_snapshot_json(&table, json, sizeof(json)) <= 0 ||
      strstr(json, "\"namespace_count\":3") == 0 ||
      strstr(json, "\"process_count\":2") == 0 ||
      strstr(json, "\"process_id\":6001") == 0 ||
      strstr(json, "\"process_id\":6002") == 0) {
    fprintf(stderr, "namespace snapshot missing expected fields: %s\n", json);
    return 1;
  }
  if (aegis_namespace_snapshot_json(&table, tiny, sizeof(tiny)) >= 0) {
    fprintf(stderr, "expected tiny namespace snapshot buffer failure\n");
    return 1;
  }
  if (aegis_namespace_destroy(&table, ns_a) == 0) {
    fprintf(stderr, "destroy should fail while namespace has members\n");
    return 1;
  }
  if (aegis_namespace_detach_process(&table, 6001u) != 0 ||
      aegis_namespace_destroy(&table, ns_a) != 0) {
    fprintf(stderr, "detach+destroy namespace failed\n");
    return 1;
  }
  return 0;
}

static int test_syscall_capability_gate_matrix(void) {
  aegis_syscall_gate_matrix_t matrix;
  uint8_t allowed = 0u;
  char json[4096];
  char tiny[32];
  aegis_syscall_gate_matrix_init(&matrix);
  if (aegis_syscall_gate_set_rule(&matrix, 100u, AEGIS_SYSCALL_CLASS_FS, 0x1u, 1u) != 0 ||
      aegis_syscall_gate_set_rule(&matrix, 200u, AEGIS_SYSCALL_CLASS_NET, 0x4u, 0u) != 0 ||
      aegis_syscall_gate_set_rule(&matrix, 300u, AEGIS_SYSCALL_CLASS_DEVICE, 0x10u, 1u) != 0) {
    fprintf(stderr, "syscall rule setup failed\n");
    return 1;
  }
  if (aegis_syscall_gate_set_process_caps(&matrix, 7001u, 0x1u | 0x4u) != 0 ||
      aegis_syscall_gate_set_process_caps(&matrix, 7002u, 0x1u) != 0) {
    fprintf(stderr, "syscall process caps setup failed\n");
    return 1;
  }
  if (aegis_syscall_gate_check(&matrix, 7001u, 100u, 1u, &allowed) != 1 || allowed != 1u) {
    fprintf(stderr, "expected syscall 100 allow for process 7001\n");
    return 1;
  }
  if (aegis_syscall_gate_check(&matrix, 7002u, 200u, 1u, &allowed) != 0 || allowed != 0u) {
    fprintf(stderr, "expected syscall 200 deny missing capability\n");
    return 1;
  }
  if (aegis_syscall_gate_check(&matrix, 7001u, 300u, 0u, &allowed) != 0 || allowed != 0u) {
    fprintf(stderr, "expected syscall 300 deny on policy gate\n");
    return 1;
  }
  if (aegis_syscall_gate_check(&matrix, 9999u, 100u, 1u, &allowed) != 0 || allowed != 0u) {
    fprintf(stderr, "expected syscall deny for missing process\n");
    return 1;
  }
  if (aegis_syscall_gate_check(&matrix, 7001u, 999u, 1u, &allowed) != 0 || allowed != 0u) {
    fprintf(stderr, "expected syscall deny for missing rule\n");
    return 1;
  }
  if (aegis_syscall_gate_snapshot_json(&matrix, json, sizeof(json)) <= 0 ||
      strstr(json, "\"schema_version\":1") == 0 ||
      strstr(json, "\"allow_count\":1") == 0 ||
      strstr(json, "\"deny_missing_rule_count\":1") == 0 ||
      strstr(json, "\"deny_missing_process_count\":1") == 0 ||
      strstr(json, "\"deny_missing_capability_count\":1") == 0 ||
      strstr(json, "\"deny_policy_gate_count\":1") == 0 ||
      strstr(json, "\"syscall_id\":100") == 0 ||
      strstr(json, "\"process_id\":7001") == 0) {
    fprintf(stderr, "syscall gate snapshot mismatch: %s\n", json);
    return 1;
  }
  if (aegis_syscall_gate_snapshot_json(&matrix, tiny, sizeof(tiny)) >= 0) {
    fprintf(stderr, "expected tiny syscall gate snapshot to fail\n");
    return 1;
  }
  if (aegis_syscall_gate_remove_process(&matrix, 7002u) != 0 ||
      aegis_syscall_gate_remove_process(&matrix, 7002u) == 0) {
    fprintf(stderr, "syscall process removal behavior mismatch\n");
    return 1;
  }
  return 0;
}

static int test_ipc_channel_quota_and_backpressure(void) {
  aegis_ipc_channel_table_t table;
  uint8_t accepted = 0u;
  char json[4096];
  char tiny[32];
  aegis_ipc_channel_table_init(&table);
  if (aegis_ipc_channel_configure(&table, 42u, 256u) != 0 ||
      aegis_ipc_channel_configure(&table, 43u, 128u) != 0) {
    fprintf(stderr, "ipc channel configure failed\n");
    return 1;
  }
  if (aegis_ipc_channel_reserve_send(&table, 42u, 200u, &accepted) != 1 || accepted != 1u) {
    fprintf(stderr, "ipc reserve send should accept below quota\n");
    return 1;
  }
  if (aegis_ipc_channel_reserve_send(&table, 42u, 80u, &accepted) != 0 || accepted != 0u) {
    fprintf(stderr, "ipc reserve send should backpressure above quota\n");
    return 1;
  }
  if (aegis_ipc_channel_drain(&table, 42u, 120u) != 0) {
    fprintf(stderr, "ipc drain should succeed\n");
    return 1;
  }
  if (aegis_ipc_channel_reserve_send(&table, 42u, 80u, &accepted) != 1 || accepted != 1u) {
    fprintf(stderr, "ipc reserve send should recover after drain\n");
    return 1;
  }
  if (aegis_ipc_channel_reserve_send(&table, 999u, 10u, &accepted) >= 0) {
    fprintf(stderr, "ipc reserve send should fail for unknown channel\n");
    return 1;
  }
  if (aegis_ipc_channel_snapshot_json(&table, json, sizeof(json)) <= 0 ||
      strstr(json, "\"schema_version\":1") == 0 ||
      strstr(json, "\"total_accepted_messages\":2") == 0 ||
      strstr(json, "\"total_dropped_messages\":1") == 0 ||
      strstr(json, "\"total_backpressure_events\":1") == 0 ||
      strstr(json, "\"channel_id\":42") == 0 ||
      strstr(json, "\"inflight_bytes\":160") == 0) {
    fprintf(stderr, "ipc snapshot mismatch: %s\n", json);
    return 1;
  }
  if (aegis_ipc_channel_snapshot_json(&table, tiny, sizeof(tiny)) >= 0) {
    fprintf(stderr, "expected tiny ipc snapshot to fail\n");
    return 1;
  }
  return 0;
}

static int test_memory_zone_accounting_and_reclaim_hooks(void) {
  aegis_memory_zone_table_t table;
  uint8_t accepted = 0u;
  char json[4096];
  char tiny[32];
  aegis_memory_zone_table_init(&table);
  if (aegis_memory_zone_configure(&table, 1u, AEGIS_MEMORY_ZONE_KERNEL, 1024u) != 0 ||
      aegis_memory_zone_configure(&table, 2u, AEGIS_MEMORY_ZONE_USER, 2048u) != 0) {
    fprintf(stderr, "memory zone configure failed\n");
    return 1;
  }
  if (aegis_memory_zone_set_reclaim_hook(&table, 1u, 1u, 256u) != 0) {
    fprintf(stderr, "memory zone reclaim hook setup failed\n");
    return 1;
  }
  if (aegis_memory_zone_charge(&table, 1u, 900u, &accepted) != 1 || accepted != 1u) {
    fprintf(stderr, "memory zone initial charge expected allow\n");
    return 1;
  }
  if (aegis_memory_zone_charge(&table, 1u, 300u, &accepted) != 1 || accepted != 1u) {
    fprintf(stderr, "memory zone reclaim-assisted charge expected allow\n");
    return 1;
  }
  if (aegis_memory_zone_charge(&table, 1u, 700u, &accepted) != 0 || accepted != 0u) {
    fprintf(stderr, "memory zone oversized charge expected deny\n");
    return 1;
  }
  if (aegis_memory_zone_charge(&table, 2u, 2100u, &accepted) != 0 || accepted != 0u) {
    fprintf(stderr, "memory zone user oversized charge expected deny\n");
    return 1;
  }
  if (aegis_memory_zone_release(&table, 1u, 100u) != 0) {
    fprintf(stderr, "memory zone release failed\n");
    return 1;
  }
  if (aegis_memory_zone_snapshot_json(&table, json, sizeof(json)) <= 0 ||
      strstr(json, "\"schema_version\":1") == 0 ||
      strstr(json, "\"denied_charges\":2") == 0 ||
      strstr(json, "\"reclaim_events\":2") == 0 ||
      strstr(json, "\"zone_id\":1") == 0 ||
      strstr(json, "\"reclaim_successes\":1") == 0) {
    fprintf(stderr, "memory zone snapshot mismatch: %s\n", json);
    return 1;
  }
  if (aegis_memory_zone_snapshot_json(&table, tiny, sizeof(tiny)) >= 0) {
    fprintf(stderr, "expected tiny memory zone snapshot failure\n");
    return 1;
  }
  return 0;
}

static int test_scheduler_remove(void) {
  aegis_scheduler_t scheduler;
  uint32_t pid = 0;
  aegis_scheduler_init(&scheduler);
  if (aegis_scheduler_add(&scheduler, 1u) != 0 ||
      aegis_scheduler_add(&scheduler, 2u) != 0 ||
      aegis_scheduler_add(&scheduler, 3u) != 0) {
    fprintf(stderr, "scheduler add failed in remove test\n");
    return 1;
  }
  if (aegis_scheduler_next(&scheduler, &pid) != 0 || pid != 1u) {
    fprintf(stderr, "remove test expected initial pid 1\n");
    return 1;
  }
  if (aegis_scheduler_remove(&scheduler, 2u) != 0) {
    fprintf(stderr, "remove pid 2 failed\n");
    return 1;
  }
  if (aegis_scheduler_count(&scheduler) != 2u) {
    fprintf(stderr, "scheduler count after remove mismatch\n");
    return 1;
  }
  if (aegis_scheduler_next(&scheduler, &pid) != 0 || pid != 3u) {
    fprintf(stderr, "expected pid 3 after removing 2\n");
    return 1;
  }
  if (aegis_scheduler_next(&scheduler, &pid) != 0 || pid != 1u) {
    fprintf(stderr, "expected pid 1 after wrap in remove test\n");
    return 1;
  }
  return 0;
}

static int test_scheduler_metrics(void) {
  aegis_scheduler_t scheduler;
  uint32_t pid = 0;
  uint32_t c1 = 0;
  uint32_t c2 = 0;
  int i;
  aegis_scheduler_init(&scheduler);
  if (aegis_scheduler_add(&scheduler, 5001u) != 0 || aegis_scheduler_add(&scheduler, 5002u) != 0) {
    fprintf(stderr, "metrics add failed\n");
    return 1;
  }
  if (aegis_scheduler_high_watermark(&scheduler) < 2u) {
    fprintf(stderr, "expected watermark to track max queue depth\n");
    return 1;
  }
  for (i = 0; i < 6; ++i) {
    if (aegis_scheduler_next(&scheduler, &pid) != 0) {
      fprintf(stderr, "metrics next failed\n");
      return 1;
    }
  }
  if (aegis_scheduler_total_dispatches(&scheduler) != 6u) {
    fprintf(stderr, "expected total dispatch count of 6\n");
    return 1;
  }
  if (aegis_scheduler_dispatch_count_for(&scheduler, 5001u, &c1) != 0 ||
      aegis_scheduler_dispatch_count_for(&scheduler, 5002u, &c2) != 0) {
    fprintf(stderr, "failed per-process dispatch lookup\n");
    return 1;
  }
  if (c1 == 0u || c2 == 0u) {
    fprintf(stderr, "expected both processes to be dispatched\n");
    return 1;
  }
  aegis_scheduler_reset_metrics(&scheduler);
  if (aegis_scheduler_total_dispatches(&scheduler) != 0u) {
    fprintf(stderr, "expected metrics reset to clear total dispatches\n");
    return 1;
  }
  return 0;
}

static int test_scheduler_preemption_tick(void) {
  aegis_scheduler_t scheduler;
  uint32_t pid = 0;
  uint8_t switched = 0;
  uint8_t reason = AEGIS_SWITCH_NONE;
  uint64_t process_start_count = 0;
  uint64_t quantum_expired_count = 0;
  uint64_t manual_yield_count = 0;
  uint64_t process_exit_count = 0;
  aegis_scheduler_init(&scheduler);
  aegis_scheduler_set_quantum(&scheduler, 2u);
  if (aegis_scheduler_add(&scheduler, 7001u) != 0 || aegis_scheduler_add(&scheduler, 7002u) != 0) {
    fprintf(stderr, "preemption add failed\n");
    return 1;
  }
  if (aegis_scheduler_on_tick_ex(&scheduler, &pid, &switched, &reason) != 0 || switched == 0 ||
      pid != 7001u || reason != AEGIS_SWITCH_PROCESS_START) {
    fprintf(stderr, "tick1 expected switch to pid 7001\n");
    return 1;
  }
  if (aegis_scheduler_on_tick_ex(&scheduler, &pid, &switched, &reason) != 0 || switched != 0 ||
      pid != 7001u || reason != AEGIS_SWITCH_NONE) {
    fprintf(stderr, "tick2 expected same pid 7001 without switch\n");
    return 1;
  }
  if (aegis_scheduler_on_tick_ex(&scheduler, &pid, &switched, &reason) != 0 || switched == 0 ||
      pid != 7002u || reason != AEGIS_SWITCH_QUANTUM_EXPIRED) {
    fprintf(stderr, "tick3 expected switch to pid 7002\n");
    return 1;
  }
  if (aegis_scheduler_on_tick_ex(&scheduler, &pid, &switched, &reason) != 0 || switched != 0 ||
      pid != 7002u || reason != AEGIS_SWITCH_NONE) {
    fprintf(stderr, "tick4 expected same pid 7002 without switch\n");
    return 1;
  }
  if (aegis_scheduler_manual_yield(&scheduler) != 0) {
    fprintf(stderr, "manual yield failed\n");
    return 1;
  }
  if (aegis_scheduler_on_tick_ex(&scheduler, &pid, &switched, &reason) != 0 || switched == 0 ||
      reason != AEGIS_SWITCH_MANUAL_YIELD) {
    fprintf(stderr, "tick5 expected manual yield context switch reason\n");
    return 1;
  }
  if (aegis_scheduler_remove(&scheduler, pid) != 0) {
    fprintf(stderr, "remove running process failed\n");
    return 1;
  }
  if (aegis_scheduler_on_tick_ex(&scheduler, &pid, &switched, &reason) != 0 || switched == 0 ||
      reason != AEGIS_SWITCH_PROCESS_EXIT) {
    fprintf(stderr, "tick6 expected process exit context switch reason\n");
    return 1;
  }
  if (aegis_scheduler_switch_reason_count(&scheduler, AEGIS_SWITCH_PROCESS_START,
                                          &process_start_count) != 0 ||
      aegis_scheduler_switch_reason_count(&scheduler, AEGIS_SWITCH_QUANTUM_EXPIRED,
                                          &quantum_expired_count) != 0 ||
      aegis_scheduler_switch_reason_count(&scheduler, AEGIS_SWITCH_MANUAL_YIELD,
                                          &manual_yield_count) != 0 ||
      aegis_scheduler_switch_reason_count(&scheduler, AEGIS_SWITCH_PROCESS_EXIT,
                                          &process_exit_count) != 0) {
    fprintf(stderr, "failed to query switch reason counters\n");
    return 1;
  }
  if (process_start_count == 0u || quantum_expired_count == 0u ||
      manual_yield_count == 0u || process_exit_count == 0u) {
    fprintf(stderr, "expected non-zero switch reason counters\n");
    return 1;
  }
  return 0;
}

static int test_scheduler_metrics_snapshot_endpoint(void) {
  aegis_scheduler_t scheduler;
  aegis_scheduler_metrics_snapshot_t snap;
  uint32_t pid = 0;
  uint8_t switched = 0;
  uint8_t reason = AEGIS_SWITCH_NONE;
  aegis_scheduler_init(&scheduler);
  aegis_scheduler_set_quantum(&scheduler, 4u);
  if (aegis_scheduler_add(&scheduler, 8101u) != 0 || aegis_scheduler_add(&scheduler, 8102u) != 0) {
    fprintf(stderr, "snapshot add failed\n");
    return 1;
  }
  if (aegis_scheduler_on_tick_ex(&scheduler, &pid, &switched, &reason) != 0) {
    fprintf(stderr, "snapshot tick failed\n");
    return 1;
  }
  if (aegis_scheduler_metrics_snapshot(&scheduler, &snap) != 0) {
    fprintf(stderr, "snapshot endpoint failed\n");
    return 1;
  }
  if (snap.queue_depth != 2u || snap.high_watermark < 2u) {
    fprintf(stderr, "snapshot queue fields invalid\n");
    return 1;
  }
  if (snap.current_pid == 0u || snap.quantum_ticks != 4u) {
    fprintf(stderr, "snapshot running fields invalid\n");
    return 1;
  }
  if (snap.schema_version != AEGIS_SCHEDULER_SNAPSHOT_SCHEMA_VERSION) {
    fprintf(stderr, "snapshot schema version invalid\n");
    return 1;
  }
  if (snap.switch_process_start_count == 0u) {
    fprintf(stderr, "expected non-zero process-start reason count\n");
    return 1;
  }
  if (snap.switch_reason_window_capacity != AEGIS_SCHEDULER_REASON_HISTOGRAM_WINDOW ||
      snap.switch_reason_window_samples == 0u ||
      snap.recent_switch_process_start_count == 0u) {
    fprintf(stderr, "snapshot windowed reason histogram fields invalid\n");
    return 1;
  }
  return 0;
}

static int test_scheduler_reason_histogram_window(void) {
  aegis_scheduler_t scheduler;
  aegis_scheduler_metrics_snapshot_t snap;
  uint32_t pid = 0;
  uint8_t switched = 0;
  uint64_t total_switches;
  uint64_t recent_switches;
  int i;
  aegis_scheduler_init(&scheduler);
  aegis_scheduler_set_quantum(&scheduler, 1u);
  if (aegis_scheduler_add(&scheduler, 9301u) != 0 || aegis_scheduler_add(&scheduler, 9302u) != 0) {
    fprintf(stderr, "histogram window add failed\n");
    return 1;
  }
  for (i = 0; i < 64; ++i) {
    if (aegis_scheduler_on_tick(&scheduler, &pid, &switched) != 0) {
      fprintf(stderr, "histogram window tick failed\n");
      return 1;
    }
  }
  if (aegis_scheduler_metrics_snapshot(&scheduler, &snap) != 0) {
    fprintf(stderr, "histogram window snapshot failed\n");
    return 1;
  }
  total_switches = snap.switch_process_start_count + snap.switch_quantum_expired_count +
                   snap.switch_process_exit_count + snap.switch_manual_yield_count;
  recent_switches = snap.recent_switch_process_start_count + snap.recent_switch_quantum_expired_count +
                    snap.recent_switch_process_exit_count + snap.recent_switch_manual_yield_count;
  if (total_switches <= AEGIS_SCHEDULER_REASON_HISTOGRAM_WINDOW) {
    fprintf(stderr, "expected more switches than histogram window\n");
    return 1;
  }
  if (snap.switch_reason_window_samples != AEGIS_SCHEDULER_REASON_HISTOGRAM_WINDOW) {
    fprintf(stderr, "expected full histogram window sample count\n");
    return 1;
  }
  if (recent_switches != snap.switch_reason_window_samples) {
    fprintf(stderr, "expected recent histogram sum to match sample count\n");
    return 1;
  }
  if (recent_switches >= total_switches) {
    fprintf(stderr, "expected recent histogram to be a windowed subset\n");
    return 1;
  }
  if (snap.recent_switch_quantum_expired_count == 0u) {
    fprintf(stderr, "expected recent histogram quantum-expired activity\n");
    return 1;
  }
  return 0;
}

static int test_scheduler_reason_histogram_custom_window_query(void) {
  aegis_scheduler_t scheduler;
  uint32_t pid = 0;
  uint8_t switched = 0;
  uint32_t applied_window = 0;
  uint64_t ps = 0;
  uint64_t qe = 0;
  uint64_t pe = 0;
  uint64_t my = 0;
  int i;
  aegis_scheduler_init(&scheduler);
  aegis_scheduler_set_quantum(&scheduler, 1u);
  if (aegis_scheduler_add(&scheduler, 9401u) != 0 || aegis_scheduler_add(&scheduler, 9402u) != 0) {
    fprintf(stderr, "custom window add failed\n");
    return 1;
  }
  for (i = 0; i < 24; ++i) {
    if (aegis_scheduler_on_tick(&scheduler, &pid, &switched) != 0) {
      fprintf(stderr, "custom window tick failed\n");
      return 1;
    }
  }
  if (aegis_scheduler_switch_reason_histogram_window(&scheduler,
                                                     8u,
                                                     &applied_window,
                                                     &ps,
                                                     &qe,
                                                     &pe,
                                                     &my) != 0) {
    fprintf(stderr, "custom window query failed\n");
    return 1;
  }
  if (applied_window != 8u) {
    fprintf(stderr, "expected applied custom window 8\n");
    return 1;
  }
  if ((ps + qe + pe + my) != 8u) {
    fprintf(stderr, "expected custom window histogram sum to equal applied window\n");
    return 1;
  }
  if (aegis_scheduler_switch_reason_histogram_window(&scheduler,
                                                     128u,
                                                     &applied_window,
                                                     &ps,
                                                     &qe,
                                                     &pe,
                                                     &my) != 0) {
    fprintf(stderr, "custom large window query failed\n");
    return 1;
  }
  if (applied_window > AEGIS_SCHEDULER_REASON_HISTOGRAM_WINDOW) {
    fprintf(stderr, "applied window exceeded max rolling capacity\n");
    return 1;
  }
  if (aegis_scheduler_switch_reason_histogram_window(&scheduler,
                                                     0u,
                                                     &applied_window,
                                                     &ps,
                                                     &qe,
                                                     &pe,
                                                     &my) == 0) {
    fprintf(stderr, "expected zero requested window to fail\n");
    return 1;
  }
  return 0;
}

static int test_scheduler_reason_histogram_custom_window_query_json(void) {
  aegis_scheduler_t scheduler;
  uint32_t pid = 0;
  uint8_t switched = 0;
  char json[512];
  int i;
  aegis_scheduler_init(&scheduler);
  aegis_scheduler_set_quantum(&scheduler, 1u);
  if (aegis_scheduler_add(&scheduler, 9501u) != 0 || aegis_scheduler_add(&scheduler, 9502u) != 0) {
    fprintf(stderr, "custom window json add failed\n");
    return 1;
  }
  for (i = 0; i < 18; ++i) {
    if (aegis_scheduler_on_tick(&scheduler, &pid, &switched) != 0) {
      fprintf(stderr, "custom window json tick failed\n");
      return 1;
    }
  }
  if (aegis_scheduler_switch_reason_histogram_window_json(&scheduler, 6u, json, sizeof(json)) <= 0) {
    fprintf(stderr, "custom window json serialization failed\n");
    return 1;
  }
  if (strstr(json, "\"schema_version\":1") == 0 ||
      strstr(json, "\"requested_window\":6") == 0 ||
      strstr(json, "\"applied_window\":6") == 0 ||
      strstr(json, "\"quantum_expired_count\":") == 0) {
    fprintf(stderr, "custom window json missing expected fields: %s\n", json);
    return 1;
  }
  if (aegis_scheduler_switch_reason_histogram_window_json(&scheduler, 0u, json, sizeof(json)) >= 0) {
    fprintf(stderr, "expected invalid requested window to fail json endpoint\n");
    return 1;
  }
  return 0;
}

static int test_scheduler_wait_latency_metrics(void) {
  aegis_scheduler_t scheduler;
  uint32_t pid = 0;
  uint8_t switched = 0;
  uint64_t wait_a = 0;
  uint64_t wait_b = 0;
  uint64_t lat_a = 0;
  uint64_t lat_b = 0;
  int i;
  aegis_scheduler_init(&scheduler);
  aegis_scheduler_set_quantum(&scheduler, 1u);
  if (aegis_scheduler_add(&scheduler, 9001u) != 0 || aegis_scheduler_add(&scheduler, 9002u) != 0) {
    fprintf(stderr, "wait metric add failed\n");
    return 1;
  }
  for (i = 0; i < 6; ++i) {
    if (aegis_scheduler_on_tick(&scheduler, &pid, &switched) != 0) {
      fprintf(stderr, "wait metric tick failed\n");
      return 1;
    }
  }
  if (aegis_scheduler_wait_ticks_for(&scheduler, 9001u, &wait_a) != 0 ||
      aegis_scheduler_wait_ticks_for(&scheduler, 9002u, &wait_b) != 0) {
    fprintf(stderr, "wait metric query failed\n");
    return 1;
  }
  if (aegis_scheduler_last_latency_for(&scheduler, 9001u, &lat_a) != 0 ||
      aegis_scheduler_last_latency_for(&scheduler, 9002u, &lat_b) != 0) {
    fprintf(stderr, "latency query failed\n");
    return 1;
  }
  if (wait_a == 0u || wait_b == 0u) {
    fprintf(stderr, "expected accumulated wait ticks to be non-zero\n");
    return 1;
  }
  if (lat_a == 0u || lat_b == 0u) {
    fprintf(stderr, "expected last wait latency to be non-zero\n");
    return 1;
  }
  return 0;
}

static int test_scheduler_wait_report(void) {
  aegis_scheduler_t scheduler;
  aegis_scheduler_wait_report_t report;
  uint32_t pid = 0;
  uint8_t switched = 0;
  int i;
  aegis_scheduler_init(&scheduler);
  aegis_scheduler_set_quantum(&scheduler, 1u);
  if (aegis_scheduler_add(&scheduler, 9101u) != 0 ||
      aegis_scheduler_add(&scheduler, 9102u) != 0 ||
      aegis_scheduler_add(&scheduler, 9103u) != 0) {
    fprintf(stderr, "wait report add failed\n");
    return 1;
  }
  for (i = 0; i < 12; ++i) {
    if (aegis_scheduler_on_tick(&scheduler, &pid, &switched) != 0) {
      fprintf(stderr, "wait report tick failed\n");
      return 1;
    }
  }
  if (aegis_scheduler_wait_report(&scheduler, &report) != 0) {
    fprintf(stderr, "wait report query failed\n");
    return 1;
  }
  if (report.max_wait_ticks == 0u || report.max_last_latency_ticks == 0u) {
    fprintf(stderr, "expected non-zero max wait/latency\n");
    return 1;
  }
  if (report.p95_wait_ticks < report.mean_wait_ticks) {
    fprintf(stderr, "expected p95 wait to be >= mean wait\n");
    return 1;
  }
  return 0;
}

static int test_scheduler_snapshot_serialization(void) {
  aegis_scheduler_t scheduler;
  aegis_scheduler_metrics_snapshot_t metrics;
  aegis_scheduler_wait_report_snapshot_t wait_snapshot;
  uint32_t pid = 0;
  uint8_t switched = 0;
  char metrics_json[512];
  char wait_json[512];
  int i;
  aegis_scheduler_init(&scheduler);
  aegis_scheduler_set_quantum(&scheduler, 2u);
  if (aegis_scheduler_add(&scheduler, 9201u) != 0 || aegis_scheduler_add(&scheduler, 9202u) != 0) {
    fprintf(stderr, "serialization add failed\n");
    return 1;
  }
  for (i = 0; i < 8; ++i) {
    if (aegis_scheduler_on_tick(&scheduler, &pid, &switched) != 0) {
      fprintf(stderr, "serialization tick failed\n");
      return 1;
    }
  }
  if (aegis_scheduler_metrics_snapshot(&scheduler, &metrics) != 0) {
    fprintf(stderr, "metrics snapshot query failed\n");
    return 1;
  }
  if (aegis_scheduler_metrics_snapshot_json(&metrics, metrics_json, sizeof(metrics_json)) <= 0) {
    fprintf(stderr, "metrics snapshot serialization failed\n");
    return 1;
  }
  if (strstr(metrics_json, "\"queue_depth\":2") == 0 ||
      strstr(metrics_json, "\"scheduler_ticks\":") == 0 ||
      strstr(metrics_json, "\"schema_version\":2") == 0 ||
      strstr(metrics_json, "\"switch_process_start_count\":") == 0 ||
      strstr(metrics_json, "\"switch_reason_window_samples\":") == 0) {
    fprintf(stderr, "metrics json missing expected fields\n");
    return 1;
  }
  if (aegis_scheduler_wait_report_snapshot(&scheduler, &wait_snapshot) != 0) {
    fprintf(stderr, "wait snapshot endpoint failed\n");
    return 1;
  }
  if (wait_snapshot.queue_depth != 2u || wait_snapshot.captured_at_tick == 0u) {
    fprintf(stderr, "wait snapshot values invalid\n");
    return 1;
  }
  if (aegis_scheduler_wait_report_snapshot_json(&wait_snapshot, wait_json, sizeof(wait_json)) <= 0) {
    fprintf(stderr, "wait snapshot serialization failed\n");
    return 1;
  }
  if (strstr(wait_json, "\"captured_at_tick\":") == 0 ||
      strstr(wait_json, "\"p95_wait_ticks\":") == 0) {
    fprintf(stderr, "wait snapshot json missing expected fields\n");
    return 1;
  }
  return 0;
}

static int test_scheduler_fairness_snapshot_json_endpoint(void) {
  aegis_scheduler_t scheduler;
  uint32_t pid = 0;
  uint8_t switched = 0;
  char json[2048];
  char tiny[32];
  int i;
  aegis_scheduler_init(&scheduler);
  aegis_scheduler_set_quantum(&scheduler, 1u);
  if (aegis_scheduler_add_with_priority(&scheduler, 9801u, AEGIS_PRIORITY_HIGH) != 0 ||
      aegis_scheduler_add_with_priority(&scheduler, 9802u, AEGIS_PRIORITY_NORMAL) != 0 ||
      aegis_scheduler_add_with_priority(&scheduler, 9803u, AEGIS_PRIORITY_LOW) != 0) {
    fprintf(stderr, "fairness snapshot add failed\n");
    return 1;
  }
  for (i = 0; i < 30; ++i) {
    if (aegis_scheduler_on_tick(&scheduler, &pid, &switched) != 0) {
      fprintf(stderr, "fairness snapshot tick failed\n");
      return 1;
    }
  }
  if (aegis_scheduler_fairness_snapshot_json(&scheduler, json, sizeof(json)) <= 0) {
    fprintf(stderr, "fairness snapshot json generation failed\n");
    return 1;
  }
  if (strstr(json, "\"schema_version\":1") == 0 ||
      strstr(json, "\"queue_depth\":3") == 0 ||
      strstr(json, "\"process_id\":9801") == 0 ||
      strstr(json, "\"dispatch_share_bps\":") == 0 ||
      strstr(json, "\"wait_ticks_total\":") == 0) {
    fprintf(stderr, "fairness snapshot json missing fields: %s\n", json);
    return 1;
  }
  if (aegis_scheduler_fairness_snapshot_json(&scheduler, tiny, sizeof(tiny)) >= 0) {
    fprintf(stderr, "expected tiny fairness snapshot buffer to fail\n");
    return 1;
  }
  return 0;
}

static int test_process_checkpoint_restore_scaffold(void) {
  aegis_process_checkpoint_table_t table;
  aegis_process_runtime_state_t runtime_a;
  aegis_process_runtime_state_t runtime_b;
  aegis_process_runtime_state_t restored;
  aegis_process_checkpoint_entry_t entry;
  uint64_t epoch_a = 0u;
  char json[4096];
  char tiny[32];
  memset(&runtime_a, 0, sizeof(runtime_a));
  memset(&runtime_b, 0, sizeof(runtime_b));
  memset(&restored, 0, sizeof(restored));
  memset(&entry, 0, sizeof(entry));

  aegis_process_checkpoint_table_init(&table);
  runtime_a.process_id = 11001u;
  runtime_a.namespace_id = 31u;
  runtime_a.thread_count = 4u;
  runtime_a.vm_bytes = 64u * 1024u * 1024u;
  runtime_a.capability_mask = 0x1Fu;
  runtime_a.policy_revision = 7u;
  runtime_a.scheduler_tick = 420u;
  runtime_a.active = 1u;
  runtime_b.process_id = 11002u;
  runtime_b.namespace_id = 31u;
  runtime_b.thread_count = 2u;
  runtime_b.vm_bytes = 20u * 1024u * 1024u;
  runtime_b.capability_mask = 0x03u;
  runtime_b.policy_revision = 2u;
  runtime_b.scheduler_tick = 421u;
  runtime_b.active = 1u;

  if (aegis_process_checkpoint_register_runtime(&table, &runtime_a) != 0 ||
      aegis_process_checkpoint_register_runtime(&table, &runtime_b) != 0) {
    fprintf(stderr, "checkpoint register runtime failed\n");
    return 1;
  }
  if (aegis_process_checkpoint_capture(&table,
                                       11001u,
                                       AEGIS_CHECKPOINT_REASON_PRE_UPDATE,
                                       500u,
                                       "pre-update",
                                       &epoch_a) != 0 ||
      epoch_a == 0u) {
    fprintf(stderr, "checkpoint capture failed\n");
    return 1;
  }
  if (aegis_process_checkpoint_query(&table, 11001u, &entry) != 0 ||
      entry.checkpoint_epoch != epoch_a ||
      entry.state.vm_bytes != runtime_a.vm_bytes ||
      strcmp(entry.tag, "pre-update") != 0) {
    fprintf(stderr, "checkpoint query mismatch\n");
    return 1;
  }
  if (aegis_process_checkpoint_restore(&table, 11001u, epoch_a + 1u, &restored) == 0) {
    fprintf(stderr, "checkpoint restore should fail on epoch mismatch\n");
    return 1;
  }
  if (aegis_process_checkpoint_restore(&table, 11001u, epoch_a, &restored) != 0 ||
      restored.process_id != 11001u ||
      restored.thread_count != runtime_a.thread_count ||
      restored.policy_revision != runtime_a.policy_revision) {
    fprintf(stderr, "checkpoint restore success path mismatch\n");
    return 1;
  }
  if (aegis_process_checkpoint_snapshot_json(&table, json, sizeof(json)) <= 0 ||
      strstr(json, "\"schema_version\":1") == 0 ||
      strstr(json, "\"capture_count\":1") == 0 ||
      strstr(json, "\"restore_count\":1") == 0 ||
      strstr(json, "\"restore_failures\":1") == 0 ||
      strstr(json, "\"process_id\":11001") == 0 ||
      strstr(json, "\"tag\":\"pre-update\"") == 0) {
    fprintf(stderr, "checkpoint snapshot json mismatch: %s\n", json);
    return 1;
  }
  if (aegis_process_checkpoint_snapshot_json(&table, tiny, sizeof(tiny)) >= 0) {
    fprintf(stderr, "expected tiny checkpoint snapshot json failure\n");
    return 1;
  }
  return 0;
}

static int test_secure_time_source_attestation(void) {
  aegis_secure_time_attestor_t attestor;
  aegis_secure_time_attestation_result_t result;
  char json[1024];
  char snapshot_json[1024];
  char tiny[32];
  memset(&attestor, 0, sizeof(attestor));
  memset(&result, 0, sizeof(result));
  aegis_secure_time_attestor_init(&attestor, 77u, 1700000000u, 1000u, 100000u);
  if (aegis_secure_time_attest(&attestor, 1700000010u, 1010u, "nonce-1", &result) != 1 ||
      result.accepted != 1u ||
      strcmp(result.reason, "ok") != 0) {
    fprintf(stderr, "secure time attestation expected pass\n");
    return 1;
  }
  if (aegis_secure_time_attest(&attestor, 1699999999u, 1011u, "nonce-2", &result) != 0 ||
      result.accepted != 0u ||
      strcmp(result.reason, "rollback_detected") != 0) {
    fprintf(stderr, "secure time rollback detection expected fail\n");
    return 1;
  }
  if (aegis_secure_time_attest(&attestor, 1700000100u, 1020u, "nonce-3", &result) != 0 ||
      result.accepted != 0u ||
      strcmp(result.reason, "drift_budget_exceeded") != 0) {
    fprintf(stderr, "secure time drift guard expected fail\n");
    return 1;
  }
  if (aegis_secure_time_attestation_json(&result, json, sizeof(json)) <= 0 ||
      strstr(json, "\"schema_version\":1") == 0 ||
      strstr(json, "\"boot_id\":77") == 0 ||
      strstr(json, "\"accepted\":0") == 0 ||
      strstr(json, "\"reason\":\"drift_budget_exceeded\"") == 0) {
    fprintf(stderr, "secure time json mismatch: %s\n", json);
    return 1;
  }
  if (aegis_secure_time_attestation_json(&result, tiny, sizeof(tiny)) >= 0) {
    fprintf(stderr, "secure time json tiny buffer should fail\n");
    return 1;
  }
  if (aegis_secure_time_attest(&attestor, 1700000011u, 1011u, "nonce-1", &result) != 0 ||
      result.accepted != 0u ||
      strcmp(result.reason, "nonce_replay_detected") != 0) {
    fprintf(stderr, "secure time nonce replay expected fail\n");
    return 1;
  }
  if (aegis_secure_time_attestor_snapshot_json(&attestor, snapshot_json, sizeof(snapshot_json)) <= 0 ||
      strstr(snapshot_json, "\"schema_version\":1") == 0 ||
      strstr(snapshot_json, "\"attestations_ok\":1") == 0 ||
      strstr(snapshot_json, "\"attestations_failed\":3") == 0 ||
      strstr(snapshot_json, "\"nonce_replay_detected\":1") == 0) {
    fprintf(stderr, "secure time snapshot mismatch: %s\n", snapshot_json);
    return 1;
  }
  return 0;
}

int main(void) {
  if (test_kernel_boot() != 0) {
    return 1;
  }
  if (test_vm_region_map_abstraction() != 0) {
    return 1;
  }
  if (test_vm_region_split_and_permission_update() != 0) {
    return 1;
  }
  if (test_ipc_envelope_format_helpers() != 0) {
    return 1;
  }
  if (test_ipc_payload_guard_helper() != 0) {
    return 1;
  }
  if (test_scheduler_round_robin() != 0) {
    return 1;
  }
  if (test_scheduler_remove() != 0) {
    return 1;
  }
  if (test_scheduler_priority_weighting() != 0) {
    return 1;
  }
  if (test_scheduler_aging_boost_fairness() != 0) {
    return 1;
  }
  if (test_scheduler_admission_limits_and_snapshot() != 0) {
    return 1;
  }
  if (test_scheduler_admission_profile_presets() != 0) {
    return 1;
  }
  if (test_scheduler_admission_profile_name_resolver() != 0) {
    return 1;
  }
  if (test_namespace_isolation_simulator() != 0) {
    return 1;
  }
  if (test_syscall_capability_gate_matrix() != 0) {
    return 1;
  }
  if (test_ipc_channel_quota_and_backpressure() != 0) {
    return 1;
  }
  if (test_memory_zone_accounting_and_reclaim_hooks() != 0) {
    return 1;
  }
  if (test_scheduler_metrics() != 0) {
    return 1;
  }
  if (test_scheduler_preemption_tick() != 0) {
    return 1;
  }
  if (test_scheduler_metrics_snapshot_endpoint() != 0) {
    return 1;
  }
  if (test_scheduler_reason_histogram_window() != 0) {
    return 1;
  }
  if (test_scheduler_reason_histogram_custom_window_query() != 0) {
    return 1;
  }
  if (test_scheduler_reason_histogram_custom_window_query_json() != 0) {
    return 1;
  }
  if (test_scheduler_wait_latency_metrics() != 0) {
    return 1;
  }
  if (test_scheduler_wait_report() != 0) {
    return 1;
  }
  if (test_scheduler_snapshot_serialization() != 0) {
    return 1;
  }
  if (test_scheduler_fairness_snapshot_json_endpoint() != 0) {
    return 1;
  }
  if (test_process_checkpoint_restore_scaffold() != 0) {
    return 1;
  }
  if (test_secure_time_source_attestation() != 0) {
    return 1;
  }
  puts("kernel simulation check passed");
  return 0;
}
