#include "capability.h"

static int capability_find_index(const aegis_capability_store_t *store, uint32_t process_id,
                                 size_t *index) {
  size_t i;
  if (store == 0 || index == 0 || process_id == 0) {
    return 0;
  }
  for (i = 0; i < store->count; ++i) {
    if (store->active[i] != 0 && store->tokens[i].process_id == process_id) {
      *index = i;
      return 1;
    }
  }
  return 0;
}

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

void aegis_capability_store_init(aegis_capability_store_t *store) {
  size_t i;
  if (store == 0) {
    return;
  }
  store->count = 0;
  for (i = 0; i < 128; ++i) {
    store->active[i] = 0;
    store->tokens[i].process_id = 0;
    store->tokens[i].permissions = AEGIS_CAP_NONE;
  }
}

int aegis_capability_issue(aegis_capability_store_t *store, uint32_t process_id,
                           uint32_t permissions) {
  size_t existing = 0;
  if (store == 0 || process_id == 0) {
    return -1;
  }
  if (capability_find_index(store, process_id, &existing)) {
    store->tokens[existing].permissions = permissions;
    return 0;
  }
  if (store->count >= 128) {
    return -1;
  }
  store->tokens[store->count].process_id = process_id;
  store->tokens[store->count].permissions = permissions;
  store->active[store->count] = 1;
  store->count += 1;
  return 0;
}

int aegis_capability_revoke(aegis_capability_store_t *store, uint32_t process_id) {
  size_t index = 0;
  if (!capability_find_index(store, process_id, &index)) {
    return -1;
  }
  store->active[index] = 0;
  store->tokens[index].permissions = AEGIS_CAP_NONE;
  return 0;
}

int aegis_capability_is_allowed(const aegis_capability_store_t *store, uint32_t process_id,
                                uint32_t requested_permissions) {
  size_t index = 0;
  if (!capability_find_index(store, process_id, &index)) {
    return 0;
  }
  return aegis_capability_validate(&store->tokens[index], requested_permissions);
}
