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

int main(void) {
  if (test_kernel_boot() != 0) {
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
  puts("kernel simulation check passed");
  return 0;
}
