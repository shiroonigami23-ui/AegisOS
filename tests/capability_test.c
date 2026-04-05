#include <stdio.h>

#include "capability.h"

static int test_capability_validate(void) {
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

static int test_capability_lifecycle(void) {
  aegis_capability_store_t store;
  aegis_capability_store_init(&store);

  if (aegis_capability_issue(&store, 77u, AEGIS_CAP_FS_READ) != 0) {
    fprintf(stderr, "expected issue to pass\n");
    return 1;
  }
  if (!aegis_capability_is_allowed(&store, 77u, AEGIS_CAP_FS_READ)) {
    fprintf(stderr, "expected process 77 to have read access\n");
    return 1;
  }
  if (aegis_capability_is_allowed(&store, 77u, AEGIS_CAP_FS_WRITE)) {
    fprintf(stderr, "expected process 77 write access to fail\n");
    return 1;
  }
  if (aegis_capability_issue(&store, 77u, AEGIS_CAP_FS_READ | AEGIS_CAP_FS_WRITE) != 0) {
    fprintf(stderr, "expected permission upgrade to pass\n");
    return 1;
  }
  if (!aegis_capability_is_allowed(&store, 77u, AEGIS_CAP_FS_WRITE)) {
    fprintf(stderr, "expected process 77 write access after upgrade\n");
    return 1;
  }
  if (aegis_capability_revoke(&store, 77u) != 0) {
    fprintf(stderr, "expected revoke to pass\n");
    return 1;
  }
  if (aegis_capability_is_allowed(&store, 77u, AEGIS_CAP_FS_READ)) {
    fprintf(stderr, "expected revoked process to fail read access\n");
    return 1;
  }
  return 0;
}

int main(void) {
  if (test_capability_validate() != 0) {
    return 1;
  }
  if (test_capability_lifecycle() != 0) {
    return 1;
  }
  puts("capability tests passed");
  return 0;
}
