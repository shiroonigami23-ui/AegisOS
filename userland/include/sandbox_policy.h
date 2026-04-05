#ifndef AEGIS_SANDBOX_POLICY_H
#define AEGIS_SANDBOX_POLICY_H

#include <stddef.h>
#include <stdint.h>

#include "capability.h"

#define AEGIS_SANDBOX_POLICY_SCHEMA_VERSION 1u

typedef struct {
  uint32_t process_id;
  uint32_t capabilities;
  uint8_t allow_fs_read;
  uint8_t allow_fs_write;
  uint8_t allow_net_client;
  uint8_t allow_net_server;
  uint8_t allow_device_io;
  uint32_t schema_version;
  uint64_t policy_revision;
} aegis_sandbox_policy_t;

int aegis_sandbox_policy_validate(const aegis_sandbox_policy_t *policy,
                                  char *reason, size_t reason_size);
int aegis_sandbox_policy_allows(const aegis_sandbox_policy_t *policy,
                                uint32_t capability_bit);
int aegis_sandbox_policy_serialize_json(const aegis_sandbox_policy_t *policy,
                                        char *output, size_t output_size);
int aegis_sandbox_policy_deserialize_json(const char *input,
                                          aegis_sandbox_policy_t *policy,
                                          char *reason, size_t reason_size);

#endif
