#ifndef __FERRUM_POLICY_H__
#define __FERRUM_POLICY_H__

#include "ferrum.h"
#include "ferrum_config.h"
#include "ferrum_redis.h"

#define FERRUM_POLICY_RESULT_CLIENT_NOT_FOUND 10000
#define FERRUM_POLICY_RESULT_SYNC_PROBLEM 10001
#define FERRUM_POLICY_RESULT_DISABLED_POLICY 10002

/**
 * @brief result of an search on policy
 *
 */
typedef struct ferrum_policy_result {
  base_object();
  uint32_t client_id;
  int32_t is_dropped;
  int32_t why;
  int32_t policy_number;
  char policy_id[FERRUM_ID_STR_LEN];
} ferrum_policy_result_t;

/**
 * @brief represent a policy row in policy hash table
 *
 */
typedef struct ferrum_policy_row {
  base_object();
  uint32_t client_id;
  int32_t is_drop;
  int32_t policy_number;
  int32_t why;
  char policy_id[FERRUM_ID_STR_LEN];
  UT_hash_handle hh;
} ferrum_policy_row_t;

typedef struct ferrum_policy {
  base_object();
  private_ const ferrum_config_t *config;
  private_ ferrum_redis_t *redis_global;
  private_ ferrum_redis_t *redis_local_table;
  private_ ferrum_redis_t *redis_local;
  private_ char redis_table_channel[FERRUM_REDIS_CHANNEL_NAME_LEN];
  private_ rebrick_timer_t *table_checker;
  private_ int64_t last_message_time;
  private_ int64_t last_command_id;
  private_ int32_t is_reset_triggered;
  private_ int64_t reset_trigger_time;
  private_ struct {
    ferrum_policy_row_t *rows;
  } table;
} ferrum_policy_t;

int32_t ferrum_policy_new(ferrum_policy_t **policy, const ferrum_config_t *config);
int32_t ferrum_policy_destroy(ferrum_policy_t *policy);
int32_t ferrum_policy_execute(const ferrum_policy_t *policy, uint32_t client_id, ferrum_policy_result_t *presult);

///////  replication part, helper functions ////////////////
typedef struct ferrum_policy_replication_message {
  base_object();
  int64_t command_id;
  char *command;
  char *arg1;
  char *arg2;
  char *arg3;
  char *arg4;
  char *arg5;
  char *arg6;
  char *arg7;
  char *arg8;
  char *arg9;

} ferrum_policy_replication_message_t;

int32_t ferrum_policy_replication_message_parse(char *str, ferrum_policy_replication_message_t *message);
int32_t ferrum_policy_replication_message_execute(ferrum_policy_t *policy, ferrum_policy_replication_message_t *msg);

#endif