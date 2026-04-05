#include "capability.h"

int aegis_capability_validate(const aegis_capability_token_t *token,
                              uint32_t requested_permissions) {
  if (token == 0) {
    return 0;
  }
  if (token->process_id == 0) {
    return 0;
  }
  return (token->permissions & requested_permissions) == requested_permissions;
}

