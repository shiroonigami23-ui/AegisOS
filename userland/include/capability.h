#ifndef AEGIS_CAPABILITY_H
#define AEGIS_CAPABILITY_H

#include <stdint.h>
#include <stddef.h>

typedef enum {
  AEGIS_CAP_NONE = 0,
  AEGIS_CAP_FS_READ = 1u << 0,
  AEGIS_CAP_FS_WRITE = 1u << 1,
  AEGIS_CAP_NET_CLIENT = 1u << 2,
  AEGIS_CAP_NET_SERVER = 1u << 3,
  AEGIS_CAP_DEVICE_IO = 1u << 4
} aegis_capability_bits_t;

typedef struct {
  uint32_t process_id;
  uint32_t permissions;
} aegis_capability_token_t;

typedef struct {
  aegis_capability_token_t tokens[128];
  uint8_t active[128];
  size_t count;
} aegis_capability_store_t;

int aegis_capability_validate(const aegis_capability_token_t *token,
                              uint32_t requested_permissions);
void aegis_capability_store_init(aegis_capability_store_t *store);
int aegis_capability_issue(aegis_capability_store_t *store, uint32_t process_id,
                           uint32_t permissions);
int aegis_capability_revoke(aegis_capability_store_t *store, uint32_t process_id);
int aegis_capability_is_allowed(const aegis_capability_store_t *store, uint32_t process_id,
                                uint32_t requested_permissions);

#endif
