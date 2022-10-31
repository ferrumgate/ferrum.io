#include "ferrum_policy.h"

int32_t ferrum_policy_new(ferrum_policy_t **policy) {
  ferrum_policy_t *tmp = new1(ferrum_policy_t);
  constructor(tmp, ferrum_policy_t);

  *policy = tmp;
  return FERRUM_SUCCESS;
}
int32_t ferrum_policy_destroy(ferrum_policy_t *policy) {
  if (policy) {
    rebrick_free(policy);
  }
  return FERRUM_SUCCESS;
}
int32_t ferrum_policy_execute(const ferrum_policy_t *policy, uint32_t client_id, ferrum_policy_result_t *presult) {
  unused(policy);
  unused(client_id);
  unused(presult);
  presult->isBlocked = 0;
  return FERRUM_SUCCESS;
}