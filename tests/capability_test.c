#include <stdio.h>

#include "capability.h"

static int run_tests(void) {
  aegis_capability_token_t token = {42u, AEGIS_CAP_FS_READ | AEGIS_CAP_NET_CLIENT};
  aegis_capability_token_t invalid_pid = {0u, AEGIS_CAP_FS_READ};

  if (!aegis_capability_validate(&token, AEGIS_CAP_FS_READ)) {
    fprintf(stderr, "expected read capability to pass\n");
    return 1;
  }
  if (aegis_capability_validate(&token, AEGIS_CAP_FS_WRITE)) {
    fprintf(stderr, "expected write capability to fail\n");
    return 1;
  }
  if (aegis_capability_validate(&invalid_pid, AEGIS_CAP_FS_READ)) {
    fprintf(stderr, "expected invalid process id to fail\n");
    return 1;
  }
  if (aegis_capability_validate(0, AEGIS_CAP_FS_READ)) {
    fprintf(stderr, "expected null token to fail\n");
    return 1;
  }
  return 0;
}

int main(void) {
  int rc = run_tests();
  if (rc != 0) {
    return rc;
  }
  puts("capability tests passed");
  return 0;
}

