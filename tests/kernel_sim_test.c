#include <stdio.h>
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
  puts("kernel simulation check passed");
  return 0;
}
