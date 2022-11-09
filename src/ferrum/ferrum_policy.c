#include "ferrum_policy.h"
#define FERRUM_POLICY_TABLE_OUT_OF_DATE_MS 5 * 60 * 1000

/* static void replication_messages(redisAsyncContext *context, void *_reply, void *_privdata) {
  unused(context);
  // ferrum_redis_t *redis = cast(context->data, ferrum_redis_t *);
  ferrum_redis_cmd_t *cmd = cast(_privdata, ferrum_redis_cmd_t *);
  ferrum_redis_reply_t *reply = cast(_reply, ferrum_redis_reply_t *);
  ferrum_policy_t *policy = cast(cmd->callback.arg1, ferrum_policy_t *);
  if (reply && reply->type == REDIS_REPLY_ARRAY && reply->elements == 1)
    if (reply->element[0]->type == REDIS_REPLY_ARRAY && reply->element[0]->elements > 1)
      if (reply->element[0]->element[1]->type == REDIS_REPLY_ARRAY && reply->element[0]->element[1]->elements) {
        for (int32_t i = 0; i < reply->element[0]->element[1]->elements; ++i) {
          ferrum_redis_reply_t *row = reply->element[0]->element[1]->element[i];
          if (row->type == REDIS_REPLY_ARRAY && row->elements) {
            if (row->element[0]->type == REDIS_REPLY_STRING) {
              ferrum_log_info("update message received id %s\n", row->element[0]->str);
            }
            if (row->elements > 1 && row->element[1]->type == REDIS_REPLY_ARRAY && row->element[1]->elements)
              if (row->element[1]->element[0]->type == REDIS_REPLY_STRING) {
                ferrum_log_info("update message received %s\n", row->element[1]->element[0]->str);
              }
          }
        }
        ferrum_log_info("update message received %s\n", reply->element[0]->element[1]->elements);
        ferrum_log_info("update message received %s\n", reply->element[0]->element[0]->str);
      }
} */

static void redis_send_reset_replication_command(ferrum_policy_t *policy);

static void clear_policy_table(ferrum_policy_t *policy) {
  ferrum_policy_row_t *el, *tmp;
  HASH_ITER(hh, policy->table.rows, el, tmp) {
    HASH_DEL(policy->table.rows, el);
    rebrick_free(el);
  }
  policy->last_command_id = 0; // important
}

int32_t ferrum_policy_replication_message_execute(ferrum_policy_t *policy,
                                                  ferrum_policy_replication_message_t *msg) {

  int32_t result;
  if (!strcmp(msg->command, "ok")) {
    // nothing todo this is only alive command
  }
  if (!strcmp(msg->command, "reset")) {
    clear_policy_table(policy);
    policy->is_reset_triggered = FALSE;
    policy->reset_trigger_time = 0;
    ferrum_log_debug("replication reset received\n");
  }
  if (!strcmp(msg->command, "update")) {
    if (policy->last_command_id >= msg->command_id)
      return REBRICK_ERR_BAD_ARGUMENT;
    if (!msg->arg1 || !msg->arg2 || !msg->arg3 || !msg->arg4 || !msg->arg5) {
      rebrick_log_error("replication update invalid args\n");
      return REBRICK_ERR_BAD_ARGUMENT;
    }

    uint32_t client_id = 0;
    result = rebrick_util_to_uint32_t(msg->arg1, &client_id);
    if (result) {
      ferrum_log_error("converting client id failed %s\n", msg->arg1);
      return REBRICK_ERR_BAD_ARGUMENT;
    }
    int32_t is_drop = 1;
    result = rebrick_util_to_int32_t(msg->arg2, &is_drop);
    if (result) {
      ferrum_log_error("converting is drop failed %s\n", msg->arg2);
      return REBRICK_ERR_BAD_ARGUMENT;
    }
    int32_t policy_number = 0;
    result = rebrick_util_to_int32_t(msg->arg3, &policy_number);
    if (result) {
      ferrum_log_error("converting policy number failed %s\n", msg->arg3);
      return REBRICK_ERR_BAD_ARGUMENT;
    }

    int32_t why = 0;
    result = rebrick_util_to_int32_t(msg->arg4, &why);
    if (result) {
      ferrum_log_error("converting why failed %s\n", msg->arg4);
      return REBRICK_ERR_BAD_ARGUMENT;
    }

    ferrum_policy_row_t *el = NULL;
    HASH_FIND(hh, policy->table.rows, &client_id, sizeof(client_id), el);
    if (!el) {
      el = new1(ferrum_policy_row_t);
      constructor(el, ferrum_policy_row_t);
      el->client_id = client_id;
      HASH_ADD(hh, policy->table.rows, client_id, sizeof(el->client_id), el);
    }
    el->client_id = client_id;
    el->is_drop = is_drop;
    el->policy_number = policy_number;
    strncpy(el->policy_id, msg->arg5, sizeof(el->policy_id) - 1);
    el->why = why;
    ferrum_log_debug("updated rule %u\n", el->client_id);
  }

  if (!strcmp(msg->command, "delete")) {
    if (policy->last_command_id >= msg->command_id)
      return REBRICK_ERR_BAD_ARGUMENT;
    if (!msg->arg1) {
      rebrick_log_error("replication update invalid args\n");
      return REBRICK_ERR_BAD_ARGUMENT;
    }
    uint32_t client_id = 0;
    result = rebrick_util_to_uint32_t(msg->arg1, &client_id);
    if (result) {
      ferrum_log_error("converting client id failed %s\n", msg->arg1);
      return REBRICK_ERR_BAD_ARGUMENT;
    }
    ferrum_policy_row_t *el = NULL;
    HASH_FIND(hh, policy->table.rows, &client_id, sizeof(client_id), el);
    if (el) {
      HASH_DEL(policy->table.rows, el);
      rebrick_free(el);
    }
    ferrum_log_debug("deleted rule %u\n", client_id);
  }

  return FERRUM_SUCCESS;
}

int32_t
ferrum_policy_replication_message_parse(char *str, ferrum_policy_replication_message_t *msg) {
  size_t count = 0;
  char *param;
  char *command_id_str = NULL;
  if (!str)
    return REBRICK_ERR_BAD_ARGUMENT;

  param = strtok(str, "/");
  while (param) {
    switch (count) {
    case 0:
      command_id_str = param;
      break;
    case 1:
      msg->command = param;
      break;
    case 2:
      msg->arg1 = param;
      break;
    case 3:
      msg->arg2 = param;
      break;
    case 4:
      msg->arg3 = param;
      break;
    case 5:
      msg->arg4 = param;
      break;
    case 6:
      msg->arg5 = param;
      break;
    case 7:
      msg->arg6 = param;
      break;
    case 8:
      msg->arg7 = param;
      break;
    case 9:
      msg->arg8 = param;
      break;
    case 10:
      msg->arg9 = param;
      break;
    default:
      break;
    }
    param = strtok(NULL, "/");
    count++;
  }
  if (count < 2) { // no data
    rebrick_log_error("not enough command\n");
    return REBRICK_ERR_BAD_ARGUMENT;
  }

  int64_t command_id_int;
  int32_t result = rebrick_util_to_int64_t(command_id_str, &command_id_int);
  if (result) {
    ferrum_log_error("converting command id failed %s\n", command_id_str);
    return REBRICK_ERR_BAD_ARGUMENT;
  }
  msg->command_id = command_id_int;
  return FERRUM_SUCCESS;
}

static void replication_messages(redisAsyncContext *context, void *_reply, void *_privdata) {
  unused(context);
  ferrum_redis_t *redis = cast(context->data, ferrum_redis_t *);
  ferrum_redis_cmd_t *cmd = cast(_privdata, ferrum_redis_cmd_t *);
  ferrum_redis_reply_t *reply = cast(_reply, ferrum_redis_reply_t *);
  ferrum_policy_t *policy = cast(cmd->callback.arg1, ferrum_policy_t *);

  int32_t result;
  int64_t time = 0;
  int64_t id = 0;
  char command[256] = {0};
  if (reply && reply->type == REDIS_REPLY_ARRAY && reply->elements == 1)
    if (reply->element[0]->type == REDIS_REPLY_ARRAY && reply->element[0]->elements > 1)
      if (reply->element[0]->element[1]->type == REDIS_REPLY_ARRAY && reply->element[0]->element[1]->elements) {
        for (size_t i = 0; i < reply->element[0]->element[1]->elements; ++i) {
          ferrum_redis_reply_t *row = reply->element[0]->element[1]->element[i];
          if (row->type == REDIS_REPLY_ARRAY && row->elements) {
            if (row->element[0]->type == REDIS_REPLY_STRING) {
              char tmp[128] = {0};
              strncpy(tmp, row->element[0]->str, sizeof(tmp) - 1);
              strncpy(redis->stream.pos, row->element[0]->str, sizeof(redis->stream.pos) - 1);
              char *val = strtok(tmp, "-");
              if (val) {
                result = rebrick_util_to_int64_t(val, &time); // no need to check result
                val = strtok(NULL, "-");
                if (val) {
                  result = rebrick_util_to_int64_t(val, &id); // no need to check result
                }
              }
            }
            if (row->elements > 1 && row->element[1]->type == REDIS_REPLY_ARRAY && row->element[1]->elements > 1) {
              if (row->element[1]->element[0]->type == REDIS_REPLY_STRING) {
                // strncpy(command, row->element[1]->element[0]->str, sizeof(command) - 1);
              }
              if (row->element[1]->element[1]->type == REDIS_REPLY_STRING) {
                strncpy(command, row->element[1]->element[1]->str, sizeof(command) - 1);
              }
            }
          }
        }
      }

  if (!time || !id || !command[0]) { // not valid data
    return;
  }

  ferrum_log_info("update message received %s\n", command);
  new2(ferrum_policy_replication_message_t, msg);
  result = ferrum_policy_replication_message_parse(command, &msg);
  if (result) { // parse errror
    return;
  }

  // wait reset command if triggered
  if (policy->is_reset_triggered && strcmp(msg.command, "reset")) {
    rebrick_log_fatal("system wait for reset command\n");
    redis_send_reset_replication_command(policy);
    return;
  }
  result = ferrum_policy_replication_message_execute(policy, &msg);
  if (result) {
    rebrick_log_fatal("msg execute failed %s\n", command);
    redis_send_reset_replication_command(policy);
    return;
  }
  policy->last_command_id = id;
  policy->last_message_time = time;
}

void redis_cmd_callback(redisAsyncContext *context, void *_reply, void *_privdata) {
  unused(context);
  unused(_reply);

  // ferrum_redis_t *redis = cast(context->data, ferrum_redis_t *);
  ferrum_redis_cmd_t *cmd = cast(_privdata, ferrum_redis_cmd_t *);
  // ferrum_redis_reply_t *reply = cast(_reply, ferrum_redis_reply_t *);
  ferrum_redis_cmd_destroy(cmd);
}
static void redis_send_reset_replication_command(ferrum_policy_t *policy) {

  ferrum_redis_cmd_t *cmd2;
  ferrum_redis_cmd_new(&cmd2, 5, 10, redis_cmd_callback, policy);
  int32_t result = ferrum_redis_send(policy->redis_local, cmd2, "publish /policy/service replicate/%s/%s/%s", policy->config->host_id, policy->config->service_id, policy->config->instance_id);
  if (result) {
    ferrum_log_error("redis send cmd failed with error:%d\n", result);
    ferrum_redis_cmd_destroy(cmd2);
    return;
  }
  policy->is_reset_triggered = TRUE;
  policy->reset_trigger_time = rebrick_util_micro_time();
  policy->last_command_id = 0;
  policy->last_message_time = 0;
  clear_policy_table(policy);
  ferrum_log_debug("sended reset replication command to %s\n", policy->redis_table_channel);
}
static void redis_send_alive_command(ferrum_policy_t *policy) {

  // send I am alive to global
  ferrum_redis_cmd_t *cmd;
  ferrum_redis_cmd_new(&cmd, 15, 110, redis_cmd_callback, policy);
  int result = ferrum_redis_send(policy->redis_local, cmd, "publish /policy/service  alive/%s/%s/%s", policy->config->host_id, policy->config->service_id, policy->config->instance_id);
  if (result) {
    ferrum_log_error("redis send cmd failed with error:%d\n", result);
    ferrum_redis_cmd_destroy(cmd);
  }

  ferrum_redis_cmd_t *cmd2;
  ferrum_redis_cmd_new(&cmd2, 5, 10, redis_cmd_callback, policy);
  result = ferrum_redis_send(policy->redis_local, cmd2, "expire %s %d", policy->redis_table_channel, 60 * 60);
  if (result) {
    ferrum_log_error("redis send cmd failed with error:%d\n", result);
    ferrum_redis_cmd_destroy(cmd2);
  }
  ferrum_log_debug("sended alive command\n");
}

static int32_t table_update_check(void *callback) {
  unused(callback);
  ferrum_policy_t *policy = cast(callback, ferrum_policy_t *);
  redis_send_alive_command(policy); // dont check return value
  int64_t now = rebrick_util_micro_time();
  int32_t reset_wait_timeout = (policy->is_reset_triggered && (now - policy->reset_trigger_time) > 30 * 1000 * 1000) ? TRUE : FALSE;
  int32_t replication_timeout = (now - policy->last_message_time >= FERRUM_POLICY_TABLE_OUT_OF_DATE_MS * 1000) ? TRUE : FALSE;
  if (reset_wait_timeout || (!policy->is_reset_triggered && replication_timeout)) {
    // table is out of date
    // check if reset sended and wait 30 seconds for receiving a reset command in stream
    if (reset_wait_timeout) {
      ferrum_log_fatal("reset wait timeout occured\n");
    } else if (replication_timeout) {
      ferrum_log_fatal("replication timeout occured\n");
    }
    redis_send_reset_replication_command(policy);
  }
  return FERRUM_SUCCESS;
}

int32_t ferrum_policy_new(ferrum_policy_t **policy, const ferrum_config_t *config) {
  ferrum_policy_t *tmp = new1(ferrum_policy_t);
  constructor(tmp, ferrum_policy_t);
  tmp->config = config;

  int32_t result = ferrum_redis_new(&tmp->redis_global, config->redis.ip,
                                    atoi(config->redis.port), config->redis.pass, 10000, 5000);
  if (result) {
    ferrum_log_error("connecting redis global failed to %s:%s with error:%d\n", config->redis.ip, config->redis.port, result);
    ferrum_policy_destroy(tmp);
    return result;
  }

  result = ferrum_redis_new(&tmp->redis_local, config->redis_local.ip,
                            atoi(config->redis_local.port), config->redis_local.pass, 10000, 5000);
  if (result) {
    ferrum_log_error("connecting redis local failed to %s:%s with error:%d\n", config->redis_local.ip, config->redis_local.port, result);
    ferrum_policy_destroy(tmp);
    return result;
  }

  snprintf(tmp->redis_table_channel, sizeof(tmp->redis_table_channel) - 1, "/policy/service/%s/%s/%s", config->host_id, config->service_id, config->instance_id);
  result = ferrum_redis_new_stream(&tmp->redis_local_table, config->redis_local.ip, atoi(config->redis_local.port), config->redis_local.pass,
                                   10000, 5000, 1000, 10000, replication_messages, tmp, tmp->redis_table_channel);
  if (result) {
    ferrum_log_error("connecting redis local failed to %s:%s with error:%d\n", config->redis_local.ip, config->redis_local.port, result);
    ferrum_policy_destroy(tmp);
    return result;
  }
  ferrum_log_info("connected to redis sub %s\n", tmp->redis_table_channel);

  result = rebrick_timer_new(&tmp->table_checker, table_update_check, tmp, 5000, TRUE);
  if (result) {
    ferrum_log_error("table update check with error:%d\n", result);
    ferrum_policy_destroy(tmp);
    return result;
  }

  *policy = tmp;
  return FERRUM_SUCCESS;
}
int32_t ferrum_policy_destroy(ferrum_policy_t *policy) {
  if (policy) {
    if (policy->table_checker)
      rebrick_timer_destroy(policy->table_checker);
    if (policy->redis_global)
      ferrum_redis_destroy(policy->redis_global);
    if (policy->redis_local)
      ferrum_redis_destroy(policy->redis_local);
    if (policy->redis_local_table)
      ferrum_redis_destroy(policy->redis_local_table);

    clear_policy_table(policy);
    rebrick_free(policy);
  }
  return FERRUM_SUCCESS;
}
int32_t ferrum_policy_execute(const ferrum_policy_t *policy, uint32_t client_id, ferrum_policy_result_t *presult) {
  unused(policy);
  unused(client_id);
  unused(presult);
  presult->client_id = client_id;
  presult->is_dropped = 1;

  if (policy->config->is_policy_disabled) { // for testing expecially
    presult->is_dropped = 0;
    presult->policy_number = 0;
    presult->why = FERRUM_POLICY_RESULT_DISABLED_POLICY;
    return FERRUM_SUCCESS;
  }
  int64_t now = rebrick_util_micro_time();

  if (now - policy->last_message_time >= FERRUM_POLICY_TABLE_OUT_OF_DATE_MS * 1000) { // update time is out of date
    // table is out of date

    presult->is_dropped = 1;
    presult->policy_number = 0;
    presult->why = FERRUM_POLICY_RESULT_SYNC_PROBLEM;
    return FERRUM_SUCCESS;
  }

  ferrum_policy_row_t *el = NULL;
  HASH_FIND(hh, policy->table.rows, &client_id, sizeof(client_id), el);
  if (!el) {
    presult->is_dropped = 1;
    presult->policy_number = 0;
    presult->why = FERRUM_POLICY_RESULT_CLIENT_NOT_FOUND;
    return FERRUM_SUCCESS;

  } else {
    presult->is_dropped = el->is_drop;
    presult->policy_number = el->policy_number;
    strncpy(presult->policy_id, el->policy_id, sizeof(presult->policy_id) - 1);
    presult->why = el->why;
    return FERRUM_SUCCESS;
  }

  return FERRUM_SUCCESS;
}