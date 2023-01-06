#include "ferrum_policy.h"

int32_t ferrum_policy_new(ferrum_policy_t **policy, ferrum_config_t *config) {
  int32_t result;
  ferrum_lmdb_t *lmdb;
  result = ferrum_lmdb_new(&lmdb, config->lmdb_folder, "ferrumgate", 3, 1073741824);
  if (result)
    return result;

  ferrum_policy_t *tmp = new1(ferrum_policy_t);
  if (!tmp) {
    ferrum_log_fatal("malloc problem\n");
    rebrick_kill_current_process(REBRICK_ERR_MALLOC);
  }
  constructor(tmp, ferrum_policy_t);
  tmp->config = config;
  tmp->lmdb = lmdb;
  *policy = tmp;
  return FERRUM_SUCCESS;
}
int32_t ferrum_policy_destroy(ferrum_policy_t *policy) {
  if (policy) {
    if (policy->lmdb) {
      ferrum_lmdb_destroy(policy->lmdb);
      policy->lmdb = NULL;
    }
    rebrick_free(policy);
  }
  return FERRUM_SUCCESS;
}
int32_t ferrum_policy_execute(const ferrum_policy_t *policy, uint32_t client_id, ferrum_policy_result_t *presult) {
  int32_t result;
  presult->client_id = client_id;
  presult->is_dropped = TRUE;
  presult->why = 0;

  if (policy->config->is_policy_disabled) { // for testing expecially
    presult->is_dropped = FALSE;
    presult->why = FERRUM_POLICY_DISABLED_POLICY;
    return FERRUM_SUCCESS;
  }

  // `/authorize/track/id/${tun.trackId}/service/id/${svc.id}`
  ferrum_lmdb_t *lmdb = policy->lmdb;
  lmdb->key.size = snprintf(lmdb->key.val, sizeof(lmdb->key.val) - 1, "/authorize/track/id/%u/service/id/%s", client_id, policy->config->service_id);
  result = ferrum_lmdb_get(lmdb, &lmdb->key, &lmdb->value);
  if (result && result != FERRUM_ERR_LMDB_ROW_NOT_FOUND) {
    presult->is_dropped = TRUE;
    presult->why = FERRUM_POLICY_EXECUTE_FAILED;
    return result;
  }

  if (result == FERRUM_ERR_LMDB_ROW_NOT_FOUND) {
    presult->is_dropped = TRUE;
    presult->why = FERRUM_POLICY_NOT_FOUND;
    return FERRUM_ERR_POLICY;
  }
  //`/${isDrop}/${result.error}/${result.rule?.id || ''}/${tun.id || ''}/${tun.userId || ''}/`
  // FERRUM_ID_STR_LEN-1 is here
  // result = sscanf(lmdb->value.val, "/%d/%d/%FERRUM_ID_STR_LEN[^/]/%FERRUM_ID_STR_LEN[^/]/%FERRUM_ID_STR_LEN[^/]/", &presult->is_dropped, &presult->why, presult->policy_id, presult->tun_id, presult->user_id);
  result = sscanf(lmdb->value.val, "/%d/%d/%31[^/]/%31[^/]/%31[^/]/", &presult->is_dropped, &presult->why, presult->policy_id, presult->tun_id, presult->user_id);
  if (result < 4) {
    presult->is_dropped = TRUE;
    presult->why = FERRUM_POLICY_INVALID_DATA;
    return FERRUM_ERR_POLICY;
  }

  return FERRUM_SUCCESS;
}
