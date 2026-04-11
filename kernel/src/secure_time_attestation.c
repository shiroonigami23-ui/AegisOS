#include "kernel.h"

#include <stdio.h>
#include <string.h>

static uint64_t abs_diff_u64(uint64_t a, uint64_t b) {
  return a >= b ? (a - b) : (b - a);
}

static int nonce_seen(const aegis_secure_time_attestor_t *attestor, const char *nonce) {
  size_t i;
  if (attestor == 0 || nonce == 0 || nonce[0] == '\0') {
    return 0;
  }
  for (i = 0; i < attestor->recent_nonce_count && i < 8u; ++i) {
    if (strcmp(attestor->recent_nonces[i], nonce) == 0) {
      return 1;
    }
  }
  return 0;
}

static void nonce_record(aegis_secure_time_attestor_t *attestor, const char *nonce) {
  size_t head;
  if (attestor == 0 || nonce == 0 || nonce[0] == '\0') {
    return;
  }
  head = attestor->recent_nonce_head % 8u;
  snprintf(attestor->recent_nonces[head], sizeof(attestor->recent_nonces[head]), "%s", nonce);
  attestor->recent_nonce_head = (uint8_t)((head + 1u) % 8u);
  if (attestor->recent_nonce_count < 8u) {
    attestor->recent_nonce_count += 1u;
  }
}

void aegis_secure_time_attestor_init(aegis_secure_time_attestor_t *attestor,
                                     uint32_t boot_id,
                                     uint64_t baseline_wallclock_epoch,
                                     uint64_t baseline_monotonic_tick,
                                     uint64_t drift_budget_ppm) {
  if (attestor == 0) {
    return;
  }
  memset(attestor, 0, sizeof(*attestor));
  attestor->boot_id = boot_id;
  attestor->last_wallclock_epoch = baseline_wallclock_epoch;
  attestor->last_monotonic_tick = baseline_monotonic_tick;
  attestor->drift_budget_ppm = drift_budget_ppm;
  attestor->initialized = 1u;
}

int aegis_secure_time_attest(aegis_secure_time_attestor_t *attestor,
                             uint64_t observed_wallclock_epoch,
                             uint64_t observed_monotonic_tick,
                             const char *nonce,
                             aegis_secure_time_attestation_result_t *result_out) {
  uint64_t delta_monotonic;
  uint64_t expected_min_wallclock;
  uint64_t expected_max_wallclock;
  uint64_t budget_seconds;
  if (attestor == 0 || result_out == 0 || attestor->initialized == 0u) {
    return -1;
  }
  memset(result_out, 0, sizeof(*result_out));
  result_out->schema_version = 1u;
  result_out->boot_id = attestor->boot_id;
  result_out->observed_wallclock_epoch = observed_wallclock_epoch;
  result_out->observed_monotonic_tick = observed_monotonic_tick;
  if (nonce != 0 && nonce[0] != '\0') {
    size_t len = strlen(nonce);
    if (len > AEGIS_TIME_ATTEST_NONCE_MAX) {
      len = AEGIS_TIME_ATTEST_NONCE_MAX;
    }
    memcpy(result_out->nonce, nonce, len);
    result_out->nonce[len] = '\0';
    result_out->nonce_size = (uint8_t)len;
    if (nonce_seen(attestor, result_out->nonce)) {
      result_out->accepted = 0u;
      snprintf(result_out->reason, sizeof(result_out->reason), "%s", "nonce_replay_detected");
      attestor->nonce_replay_detected += 1u;
      attestor->attestations_failed += 1u;
      return 0;
    }
  }

  if (observed_monotonic_tick < attestor->last_monotonic_tick ||
      observed_wallclock_epoch < attestor->last_wallclock_epoch) {
    result_out->accepted = 0u;
    snprintf(result_out->reason, sizeof(result_out->reason), "%s", "rollback_detected");
    attestor->rollback_detected += 1u;
    attestor->attestations_failed += 1u;
    return 0;
  }

  delta_monotonic = observed_monotonic_tick - attestor->last_monotonic_tick;
  budget_seconds = (delta_monotonic * attestor->drift_budget_ppm) / 1000000u;
  if (budget_seconds == 0u && delta_monotonic > 0u) {
    budget_seconds = 1u;
  }
  expected_min_wallclock = attestor->last_wallclock_epoch + delta_monotonic;
  expected_max_wallclock = expected_min_wallclock + budget_seconds;
  result_out->expected_min_wallclock_epoch = expected_min_wallclock;
  result_out->expected_max_wallclock_epoch = expected_max_wallclock;
  result_out->drift_budget_ppm = attestor->drift_budget_ppm;

  if (observed_wallclock_epoch < expected_min_wallclock ||
      observed_wallclock_epoch > expected_max_wallclock) {
    uint64_t drift = abs_diff_u64(observed_wallclock_epoch, expected_min_wallclock);
    (void)drift;
    result_out->accepted = 0u;
    snprintf(result_out->reason, sizeof(result_out->reason), "%s", "drift_budget_exceeded");
    attestor->drift_violations += 1u;
    attestor->attestations_failed += 1u;
    return 0;
  }

  result_out->accepted = 1u;
  snprintf(result_out->reason, sizeof(result_out->reason), "%s", "ok");
  attestor->last_monotonic_tick = observed_monotonic_tick;
  attestor->last_wallclock_epoch = observed_wallclock_epoch;
  attestor->attestations_ok += 1u;
  nonce_record(attestor, result_out->nonce);
  return 1;
}

int aegis_secure_time_attestation_json(const aegis_secure_time_attestation_result_t *result,
                                       char *out,
                                       size_t out_size) {
  int written;
  if (result == 0 || out == 0 || out_size == 0u) {
    return -1;
  }
  written = snprintf(out,
                     out_size,
                     "{\"schema_version\":%u,\"boot_id\":%u,\"observed_wallclock_epoch\":%llu,"
                     "\"observed_monotonic_tick\":%llu,\"expected_min_wallclock_epoch\":%llu,"
                     "\"expected_max_wallclock_epoch\":%llu,\"drift_budget_ppm\":%llu,"
                     "\"accepted\":%u,\"nonce\":\"%s\",\"reason\":\"%s\"}",
                     (unsigned int)result->schema_version,
                     (unsigned int)result->boot_id,
                     (unsigned long long)result->observed_wallclock_epoch,
                     (unsigned long long)result->observed_monotonic_tick,
                     (unsigned long long)result->expected_min_wallclock_epoch,
                     (unsigned long long)result->expected_max_wallclock_epoch,
                     (unsigned long long)result->drift_budget_ppm,
                     (unsigned int)result->accepted,
                     result->nonce,
                     result->reason);
  if (written < 0 || (size_t)written >= out_size) {
    return -1;
  }
  return written;
}

int aegis_secure_time_attestor_snapshot_json(const aegis_secure_time_attestor_t *attestor,
                                             char *out,
                                             size_t out_size) {
  int written;
  if (attestor == 0 || out == 0 || out_size == 0u || attestor->initialized == 0u) {
    return -1;
  }
  written = snprintf(out,
                     out_size,
                     "{\"schema_version\":1,\"boot_id\":%u,\"last_wallclock_epoch\":%llu,"
                     "\"last_monotonic_tick\":%llu,\"drift_budget_ppm\":%llu,"
                     "\"attestations_ok\":%llu,\"attestations_failed\":%llu,"
                     "\"rollback_detected\":%llu,\"drift_violations\":%llu,"
                     "\"nonce_replay_detected\":%llu}",
                     (unsigned int)attestor->boot_id,
                     (unsigned long long)attestor->last_wallclock_epoch,
                     (unsigned long long)attestor->last_monotonic_tick,
                     (unsigned long long)attestor->drift_budget_ppm,
                     (unsigned long long)attestor->attestations_ok,
                     (unsigned long long)attestor->attestations_failed,
                     (unsigned long long)attestor->rollback_detected,
                     (unsigned long long)attestor->drift_violations,
                     (unsigned long long)attestor->nonce_replay_detected);
  if (written < 0 || (size_t)written >= out_size) {
    return -1;
  }
  return written;
}
