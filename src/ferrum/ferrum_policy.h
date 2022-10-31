#ifndef __FERRUM_POLICY_H__
#define __FERRUM_POLICY_H__

#include "ferrum.h"

typedef struct ferrum_policy_result {
  base_object();
  int32_t isBlocked;
  int32_t why;
  int32_t policyNumber;
} ferrum_policy_result_t;

typedef struct ferrum_policy {
  base_object();
} ferrum_policy_t;

int32_t ferrum_policy_new(ferrum_policy_t **policy);
int32_t ferrum_policy_destroy(ferrum_policy_t *policy);
int32_t ferrum_policy_execute(const ferrum_policy_t *policy, uint32_t client_id, ferrum_policy_result_t *presult);

#endif