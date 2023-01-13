#ifndef __FERRUM_POLICY_H__
#define __FERRUM_POLICY_H__

#include "ferrum.h"
#include "ferrum_lmdb.h"
#include "ferrum_config.h"

/*  job.admin policyService.ts
    ClientNotFound = 10000,
    InvalidData = 10001,
    NotFound = 10002,
    ExecuteFailed = 10003,
    DisabledPolicy=10004
    */
#define FERRUM_POLICY_CLIENT_NOT_FOUND 10000
#define FERRUM_POLICY_INVALID_DATA 10001
#define FERRUM_POLICY_NOT_FOUND 10002
#define FERRUM_POLICY_EXECUTE_FAILED 10003
#define FERRUM_POLICY_DISABLED_POLICY 10004

/**
 * @brief result of an search on policy
 *
 */
typedef struct ferrum_policy_result {
  base_object();
  uint32_t client_id;
  int32_t is_dropped;
  int32_t why;
  char policy_id[FERRUM_ID_STR_LEN];
  char tun_id[FERRUM_ID_BIG_STR_LEN];
  char user_id[FERRUM_ID_STR_LEN];
  char client_ip[REBRICK_IP_STR_LEN];
  char client_port[REBRICK_PORT_STR_LEN];
} ferrum_policy_result_t;

typedef struct ferrum_policy {
  base_object();
  ferrum_config_t *config;
  ferrum_lmdb_t *lmdb;
} ferrum_policy_t;

int32_t ferrum_policy_new(ferrum_policy_t **policy, ferrum_config_t *config);
int32_t ferrum_policy_destroy(ferrum_policy_t *policy);
int32_t ferrum_policy_execute(const ferrum_policy_t *policy, uint32_t client_id, ferrum_policy_result_t *presult);

#endif