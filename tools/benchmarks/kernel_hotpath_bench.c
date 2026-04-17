#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#if defined(_WIN32)
#include <windows.h>
#endif

#include "kernel.h"

typedef struct {
  uint64_t total_ns;
  double ns_per_op;
  double ops_per_sec;
} bench_result_t;

static uint64_t now_ns(void) {
#if defined(_WIN32)
  LARGE_INTEGER counter;
  LARGE_INTEGER frequency;
  if (!QueryPerformanceFrequency(&frequency)) {
    return 0u;
  }
  if (!QueryPerformanceCounter(&counter)) {
    return 0u;
  }
  return (uint64_t)((counter.QuadPart * 1000000000ull) / (uint64_t)frequency.QuadPart);
#else
#if defined(CLOCK_MONOTONIC)
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
  }
#endif
  clock_t ticks = clock();
  if (ticks < 0) {
    return 0u;
  }
  return (uint64_t)(((double)ticks * 1000000000.0) / (double)CLOCKS_PER_SEC);
#endif
}

static bench_result_t build_result(uint64_t elapsed_ns, uint32_t iterations) {
  bench_result_t out;
  out.total_ns = elapsed_ns;
  if (iterations == 0u || elapsed_ns == 0u) {
    out.ns_per_op = 0.0;
    out.ops_per_sec = 0.0;
    return out;
  }
  out.ns_per_op = (double)elapsed_ns / (double)iterations;
  out.ops_per_sec = ((double)iterations * 1000000000.0) / (double)elapsed_ns;
  return out;
}

static int run_scheduler_bench(uint32_t iterations, bench_result_t *out) {
  aegis_scheduler_t scheduler;
  uint32_t pid = 0u;
  uint64_t start_ns;
  uint64_t end_ns;
  uint32_t i;

  if (out == 0 || iterations == 0u) {
    return -1;
  }

  aegis_scheduler_init(&scheduler);
  for (i = 0u; i < 32u; ++i) {
    uint8_t priority = (uint8_t)((i % 3u) + 1u);
    if (aegis_scheduler_add_with_priority(&scheduler, 20000u + i, priority) != 0) {
      return -1;
    }
  }

  start_ns = now_ns();
  for (i = 0u; i < iterations; ++i) {
    scheduler.scheduler_ticks += 1u;
    if (aegis_scheduler_next(&scheduler, &pid) != 0) {
      return -1;
    }
  }
  end_ns = now_ns();
  *out = build_result(end_ns - start_ns, iterations);
  return 0;
}

static int run_namespace_translate_bench(uint32_t iterations, bench_result_t *out) {
  aegis_namespace_table_t table;
  uint32_t namespace_id = 0u;
  uint32_t local_pid = 0u;
  uint32_t global_pid = 0u;
  uint64_t start_ns;
  uint64_t end_ns;
  uint32_t i;

  if (out == 0 || iterations == 0u) {
    return -1;
  }

  aegis_namespace_table_init(&table);
  if (aegis_namespace_create(&table, 1u, &namespace_id) != 0) {
    return -1;
  }
  if (aegis_namespace_attach_process(&table, 30001u, namespace_id, &local_pid) != 0) {
    return -1;
  }

  start_ns = now_ns();
  for (i = 0u; i < iterations; ++i) {
    if (aegis_namespace_translate_local_to_global(&table, namespace_id, local_pid, &global_pid) != 0) {
      return -1;
    }
  }
  end_ns = now_ns();

  if (global_pid != 30001u) {
    return -1;
  }

  *out = build_result(end_ns - start_ns, iterations);
  return 0;
}

static int run_namespace_inspect_bench(uint32_t iterations, bench_result_t *out) {
  aegis_namespace_table_t table;
  uint32_t namespace_id = 0u;
  uint32_t local_pid = 0u;
  uint32_t local_pid_2 = 0u;
  uint8_t allowed = 0u;
  uint64_t start_ns;
  uint64_t end_ns;
  uint32_t i;

  if (out == 0 || iterations == 0u) {
    return -1;
  }

  aegis_namespace_table_init(&table);
  if (aegis_namespace_create(&table, 1u, &namespace_id) != 0) {
    return -1;
  }
  if (aegis_namespace_attach_process(&table, 31001u, namespace_id, &local_pid) != 0 ||
      aegis_namespace_attach_process(&table, 31002u, namespace_id, &local_pid_2) != 0) {
    return -1;
  }

  if (aegis_namespace_can_inspect(&table, 31001u, 31002u, &allowed) != 0 || allowed == 0u) {
    return -1;
  }

  start_ns = now_ns();
  for (i = 0u; i < iterations; ++i) {
    if (aegis_namespace_can_inspect(&table, 31001u, 31002u, &allowed) != 0) {
      return -1;
    }
  }
  end_ns = now_ns();

  if (allowed == 0u || local_pid == 0u || local_pid_2 == 0u) {
    return -1;
  }

  *out = build_result(end_ns - start_ns, iterations);
  return 0;
}

static int run_ipc_hotpath_bench(uint32_t iterations, bench_result_t *out) {
  aegis_ipc_channel_table_t table;
  uint8_t accepted = 0u;
  uint64_t start_ns;
  uint64_t end_ns;
  uint32_t i;

  if (out == 0 || iterations == 0u) {
    return -1;
  }

  aegis_ipc_channel_table_init(&table);
  if (aegis_ipc_channel_configure(&table, 77u, 1024u) != 0) {
    return -1;
  }

  start_ns = now_ns();
  for (i = 0u; i < iterations; ++i) {
    if (aegis_ipc_channel_reserve_send(&table, 77u, 32u, &accepted) < 0 || accepted == 0u) {
      return -1;
    }
    if (aegis_ipc_channel_drain(&table, 77u, 32u) != 0) {
      return -1;
    }
  }
  end_ns = now_ns();

  *out = build_result(end_ns - start_ns, iterations);
  return 0;
}

static int run_memory_hotpath_bench(uint32_t iterations, bench_result_t *out) {
  aegis_memory_zone_table_t table;
  uint8_t accepted = 0u;
  uint64_t start_ns;
  uint64_t end_ns;
  uint32_t i;

  if (out == 0 || iterations == 0u) {
    return -1;
  }

  aegis_memory_zone_table_init(&table);
  if (aegis_memory_zone_configure(&table, 9u, AEGIS_MEMORY_ZONE_USER, 1024u * 1024u) != 0) {
    return -1;
  }

  start_ns = now_ns();
  for (i = 0u; i < iterations; ++i) {
    if (aegis_memory_zone_charge(&table, 9u, 64u, &accepted) < 0 || accepted == 0u) {
      return -1;
    }
    if (aegis_memory_zone_release(&table, 9u, 64u) != 0) {
      return -1;
    }
  }
  end_ns = now_ns();

  *out = build_result(end_ns - start_ns, iterations);
  return 0;
}

int main(int argc, char **argv) {
  uint32_t iterations = 200000u;
  bench_result_t scheduler_result;
  bench_result_t namespace_translate_result;
  bench_result_t namespace_inspect_result;
  bench_result_t ipc_result;
  bench_result_t memory_result;

  if (argc > 1) {
    unsigned long parsed = strtoul(argv[1], 0, 10);
    if (parsed == 0ul || parsed > 20000000ul) {
      fprintf(stderr, "invalid iterations value\n");
      return 2;
    }
    iterations = (uint32_t)parsed;
  }

  if (run_scheduler_bench(iterations, &scheduler_result) != 0 ||
      run_namespace_translate_bench(iterations, &namespace_translate_result) != 0 ||
      run_namespace_inspect_bench(iterations, &namespace_inspect_result) != 0 ||
      run_ipc_hotpath_bench(iterations, &ipc_result) != 0 ||
      run_memory_hotpath_bench(iterations, &memory_result) != 0) {
    fprintf(stderr, "benchmark execution failed\n");
    return 1;
  }

  printf("{\"schema_version\":1,\"iterations\":%u,"
         "\"scheduler_next\":{\"total_ns\":%llu,\"ns_per_op\":%.3f,\"ops_per_sec\":%.3f},"
         "\"namespace_translate_local_to_global\":{\"total_ns\":%llu,\"ns_per_op\":%.3f,\"ops_per_sec\":%.3f},"
         "\"namespace_can_inspect\":{\"total_ns\":%llu,\"ns_per_op\":%.3f,\"ops_per_sec\":%.3f},"
         "\"ipc_reserve_send_plus_drain\":{\"total_ns\":%llu,\"ns_per_op\":%.3f,\"ops_per_sec\":%.3f},"
         "\"memory_charge_plus_release\":{\"total_ns\":%llu,\"ns_per_op\":%.3f,\"ops_per_sec\":%.3f}}\n",
         iterations,
         (unsigned long long)scheduler_result.total_ns,
         scheduler_result.ns_per_op,
         scheduler_result.ops_per_sec,
         (unsigned long long)namespace_translate_result.total_ns,
         namespace_translate_result.ns_per_op,
         namespace_translate_result.ops_per_sec,
         (unsigned long long)namespace_inspect_result.total_ns,
         namespace_inspect_result.ns_per_op,
         namespace_inspect_result.ops_per_sec,
         (unsigned long long)ipc_result.total_ns,
         ipc_result.ns_per_op,
         ipc_result.ops_per_sec,
         (unsigned long long)memory_result.total_ns,
         memory_result.ns_per_op,
         memory_result.ops_per_sec);
  return 0;
}
