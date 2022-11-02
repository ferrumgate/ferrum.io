#include "ferrum_policy.h"
#define FERRUM_POLICY_TABLE_OUT_OF_DATE_MS 30000

static void redis_send_reset_replication_command(ferrum_policy_t *policy);

static void clear_policy_table(ferrum_policy_t *policy) {
  ferrum_policy_row_t *el, *tmp;
  HASH_ITER(hh, policy->table.rows, el, tmp) {
    HASH_DEL(policy->table.rows, el);
    rebrick_free(el);
  }
  policy->last_command_id = -1; // important
}

int32_t ferrum_policy_replication_message_execute(ferrum_policy_t *policy,
                                                  ferrum_policy_replication_message_t *msg) {
  policy->last_command_id = msg->command_id;
  int32_t result;
  if (!strcmp(msg->command, "ok")) {
    // nothing todo this is only alive command
  }
  if (!strcmp(msg->command, "reset")) {
    clear_policy_table(policy);
    policy->is_reset_triggered = FALSE;
    ferrum_log_debug("replication reset received\n");
  }
  if (!strcmp(msg->command, "update")) {
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
    ferrum_log_debug("deleted rule %u\n", el->client_id);
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
  // ferrum_redis_t *redis = cast(context->data, ferrum_redis_t *);
  ferrum_redis_cmd_t *cmd = cast(_privdata, ferrum_redis_cmd_t *);
  ferrum_redis_reply_t *reply = cast(_reply, ferrum_redis_reply_t *);
  ferrum_policy_t *policy = cast(cmd->callback.arg1, ferrum_policy_t *);
  policy->last_message_time = rebrick_util_micro_time(); // important
  if (reply && reply->type == REDIS_REPLY_ARRAY && reply->elements == 3 && reply->element[2]->type == REDIS_REPLY_STRING && reply->element[2]->str) {
    ferrum_log_info("update message received %s\n", reply->element[2]->str);
    if (!reply->element[2]->str[0]) // empty message
      return;
    new2(ferrum_policy_replication_message_t, msg);
    int32_t result = ferrum_policy_replication_message_parse(reply->element[2]->str, &msg);
    if (result) { // parse errror
      return;
    }
    if (msg.command_id <= policy->last_command_id) {
      rebrick_log_fatal("last command is lower %lld:%lld\n", policy->last_command_id, msg.command_id);
      redis_send_reset_replication_command(policy);
      return;
    }
    if (policy->is_reset_triggered && strcmp(msg.command, "reset")) {
      rebrick_log_fatal("system wait for reset command\n");
      redis_send_reset_replication_command(policy);

    } else
      result = ferrum_policy_replication_message_execute(policy, &msg);
  }
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
  policy->is_reset_triggered = TRUE;
  ferrum_redis_cmd_t *cmd2;
  ferrum_redis_cmd_new(&cmd2, 5, 10, redis_cmd_callback, policy);
  int32_t result = ferrum_redis_send(policy->redis_main, cmd2, "publish /policy/service connect/%s/%s/%s", policy->config->host_id, policy->config->service_id, policy->config->instance_id);
  if (result) {
    ferrum_log_error("redis send cmd failed with error:%d\n", result);
    ferrum_redis_cmd_destroy(cmd2);
  }
  ferrum_log_debug("sended reset replication command\n");
}
static void redis_send_alive_command(ferrum_policy_t *policy) {

  // send I am alive
  ferrum_redis_cmd_t *cmd;
  ferrum_redis_cmd_new(&cmd, 15, 110, redis_cmd_callback, policy);
  int result = ferrum_redis_send(policy->redis_main, cmd, "publish /policy/service alive/%s/%s/%s", policy->config->host_id, policy->config->service_id, policy->config->instance_id);
  if (result) {
    ferrum_log_error("redis send cmd failed with error:%d\n", result);
    ferrum_redis_cmd_destroy(cmd);
  }
  ferrum_log_debug("sended alive command\n");
}

static int32_t table_update_check(void *callback) {
  unused(callback);
  ferrum_policy_t *policy = cast(callback, ferrum_policy_t *);
  redis_send_alive_command(policy); // dont check return value
  int64_t now = rebrick_util_micro_time();
  if (now - policy->last_message_time >= FERRUM_POLICY_TABLE_OUT_OF_DATE_MS * 1000) {
    // table is out of date

    redis_send_reset_replication_command(policy);
  }
  return FERRUM_SUCCESS;
}

int32_t ferrum_policy_new(ferrum_policy_t **policy, const ferrum_config_t *config) {
  ferrum_policy_t *tmp = new1(ferrum_policy_t);
  constructor(tmp, ferrum_policy_t);
  tmp->config = config;

  int32_t result = ferrum_redis_new(&tmp->redis_main, config->redis.ip,
                                    atoi(config->redis.port), 10000, 5000);
  if (result) {
    ferrum_log_error("connecting redis failed to %s:%s with error:%d\n", config->redis.ip, config->redis.port, result);
    ferrum_policy_destroy(tmp);
    return result;
  }

  snprintf(tmp->redis_table_channel, sizeof(tmp->redis_table_channel) - 1, "/policy/service/%s/%s/%s", config->host_id, config->service_id, config->instance_id);
  result = ferrum_redis_new_sub(&tmp->redis_table, config->redis.ip, atoi(config->redis.port),
                                10000, 5000, replication_messages, tmp, tmp->redis_table_channel);
  if (result) {
    ferrum_log_error("connecting redis failed to %s:%s with error:%d\n", config->redis.ip, config->redis.port, result);
    ferrum_policy_destroy(tmp);
    return result;
  }

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
    if (policy->redis_main)
      ferrum_redis_destroy(policy->redis_main);
    if (policy->redis_table)
      ferrum_redis_destroy(policy->redis_table);
    if (policy->table_checker)
      rebrick_timer_destroy(policy->table_checker);
    rebrick_free(policy);
  }
  return FERRUM_SUCCESS;
}
int32_t ferrum_policy_execute(const ferrum_policy_t *policy, uint32_t client_id, ferrum_policy_result_t *presult) {
  unused(policy);
  unused(client_id);
  unused(presult);
  presult->is_dropped = 0;
  return FERRUM_SUCCESS;
}