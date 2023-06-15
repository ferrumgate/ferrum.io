#include "ferrum_authz_db.h"
int32_t ferrum_authz_db_new(ferrum_authz_db_t **authz, ferrum_config_t *config) {
  int32_t result;
  ferrum_lmdb_t *lmdb;
  result = ferrum_lmdb_new(&lmdb, config->db_folder[0] ? config->db_folder : config->authz_db_folder, "authz", 24, 1073741824);
  if (result)
    return result;
  ferrum_log_info("authz lmdb folder:%s\n", config->authz_db_folder);

  ferrum_authz_db_t *tmp = new1(ferrum_authz_db_t);
  if (!tmp) {
    ferrum_log_fatal("malloc problem\n");
    rebrick_kill_current_process(REBRICK_ERR_MALLOC);
  }
  constructor(tmp, ferrum_authz_db_t);
  tmp->config = config;
  tmp->lmdb = lmdb;
  *authz = tmp;
  return FERRUM_SUCCESS;
}
int32_t ferrum_authz_db_destroy(ferrum_authz_db_t *authz) {
  if (authz) {
    if (authz->lmdb) {
      ferrum_lmdb_destroy(authz->lmdb);
      authz->lmdb = NULL;
    }
    rebrick_free(authz);
  }
  return FERRUM_SUCCESS;
}

int32_t ferrum_authz_db_service_user_row_destroy(ferrum_authz_db_service_user_row_t *row) {
  if (row) {
    if (row->rows) {
      for (size_t i = 0; i < row->rows_len; ++i) {
        if (row->rows[i].authz_id)
          rebrick_free(row->rows[i].authz_id);
        if (row->rows[i].user_or_group_ids)
          rebrick_free(row->rows[i].user_or_group_ids);
      }
      rebrick_free(row->rows);
    }
    rebrick_free(row);
  }
  return FERRUM_SUCCESS;
}

int32_t ferrum_authz_db_get_service_user_data(const ferrum_authz_db_t *authz_db, const char *service_id, ferrum_authz_db_service_user_row_t **row) {

  *row = NULL;
  ferrum_lmdb_t *lmdb = authz_db->lmdb;
  lmdb->root->key.size = snprintf(lmdb->root->key.val, sizeof(lmdb->root->key.val) - 1, "/authz/service/id/%s/user/list", service_id);
  int32_t result = ferrum_lmdb_get(lmdb, &lmdb->root->key, &lmdb->root->value);
  if (result) {
    if (result == FERRUM_ERR_LMDB) {
      ferrum_log_debug("query local authz service %s error:%d\n", service_id, result);
      return FERRUM_ERR_AUTHZ_DB;
    }
    ferrum_log_debug("query local authz service %s not found\n", service_id);
    // ferrum_lmdb_list_all(lmdb);
    return FERRUM_SUCCESS; // authz is empty
  }
  char errbuf[200] = {0};
  ferrum_log_debug("query local authz service %s data \n%s\n", service_id, lmdb->root->value.val);
  toml_table_t *conf = toml_parse(lmdb->root->value.val, errbuf, sizeof(errbuf));
  if (!conf) {
    ferrum_log_debug("query local authz service %s parse error %s\n", service_id, errbuf);
    return FERRUM_ERR_AUTHZ_DB_PARSE;
  }

  toml_array_t *rules = toml_array_in(conf, "rules");
  if (!rules) {
    ferrum_log_debug("query local authz %s cannot read rules error:%s\n", service_id, errbuf);
    toml_free(conf);
    return FERRUM_SUCCESS;
  }
  new4(ferrum_authz_db_service_user_row_t, authz_row);
  authz_row->rows = new_array(struct authz_service_user_data, 16);
  if_is_null_then_die(authz_row->rows, "malloc problem\n");
  authz_row->rows_len = 0;
  authz_row->rows_len_real = 16;

  for (size_t i = 0;; i++) {
    toml_table_t *tmp = toml_table_at(rules, i);
    if (!tmp)
      break;

    // realloc array
    if (i == authz_row->rows_len_real) {
      authz_row->rows = rebrick_realloc(authz_row->rows, sizeof(struct authz_service_user_data) * (authz_row->rows_len_real + 16));
      if_is_null_then_die(authz_row->rows, "malloc problem\n");
      authz_row->rows_len_real += 16;
    }
    // important
    fill_zero(authz_row->rows + i, sizeof(struct authz_service_user_data));
    toml_datum_t user_or_group_ids = toml_string_in(tmp, "userOrgroupIds");
    if (user_or_group_ids.ok) {
      size_t len = strlen(user_or_group_ids.u.s);
      rebrick_malloc2(authz_row->rows[i].user_or_group_ids, len + 1);
      memcpy(authz_row->rows[i].user_or_group_ids, user_or_group_ids.u.s, len);
      rebrick_free(user_or_group_ids.u.s);
    }
    toml_datum_t authz_id = toml_string_in(tmp, "id");
    if (authz_id.ok) {
      size_t len = strlen(authz_id.u.s);
      rebrick_malloc2(authz_row->rows[i].authz_id, len + 1);
      memcpy(authz_row->rows[i].authz_id, authz_id.u.s, len);
      rebrick_free(authz_id.u.s);
    }
    // toml_free(tmp);
    authz_row->rows_len++;
  }

  toml_free(conf);
  *row = authz_row;
  ferrum_log_debug("query local authz service %s parsed\n", service_id);
  return FERRUM_SUCCESS;
}

int32_t ferrum_authz_db_get_service_user_update_time(const ferrum_authz_db_t *authz_db, const char *service_id, int64_t *update_time) {
  ferrum_lmdb_t *lmdb = authz_db->lmdb;
  lmdb->root->key.size = snprintf(lmdb->root->key.val, sizeof(lmdb->root->key.val) - 1, "/authz/service/id/%s/user/list/updateTime", service_id);
  int32_t result = ferrum_lmdb_get(lmdb, &lmdb->root->key, &lmdb->root->value);
  *update_time = 0;
  if (result) {
    if (result == FERRUM_ERR_LMDB) {
      ferrum_log_error("query local authz service %s update time error:%d\n", service_id, result);
      return FERRUM_ERR_AUTHZ_DB;
    }
    ferrum_log_debug("query local authz service %s  update time not found\n", service_id);
    return FERRUM_SUCCESS; // authz is empty
  }
  if (lmdb->root->value.size)
    rebrick_util_to_int64_t(lmdb->root->value.val, update_time);
  ferrum_log_debug("query local authz service %s  update time %" PRId64 "\n", service_id, *update_time);
  return FERRUM_SUCCESS;
}

int32_t ferrum_authz_db_authz_row_destroy(ferrum_authz_db_authz_row_t *row) {
  if (row) {
    if (row->content) {
      rebrick_free(row->content);
    }
    rebrick_free(row);
  }
  return FERRUM_SUCCESS;
}

int32_t ferrum_authz_db_get_authz_update_time(const ferrum_authz_db_t *authz_db, const char *authz_id, int64_t *update_time) {
  ferrum_lmdb_t *lmdb = authz_db->lmdb;
  lmdb->root->key.size = snprintf(lmdb->root->key.val, sizeof(lmdb->root->key.val) - 1, "/authz/id/%s/updateTime", authz_id);
  int32_t result = ferrum_lmdb_get(lmdb, &lmdb->root->key, &lmdb->root->value);
  *update_time = 0;
  if (result) {
    if (result == FERRUM_ERR_LMDB) {
      ferrum_log_error("query local authz %s update time error:%d\n", authz_id, result);
      return FERRUM_ERR_AUTHZ_DB;
    }
    ferrum_log_debug("query local authz %s  update time not found\n", authz_id);
    return FERRUM_SUCCESS; // authz is empty
  }
  rebrick_util_to_int64_t(lmdb->root->value.val, update_time);
  ferrum_log_debug("query local authz %s  update time %" PRId64 "\n", authz_id, *update_time);
  return FERRUM_SUCCESS;
}

int32_t ferrum_authz_db_get_authz_data(const ferrum_authz_db_t *authz_db, const char *authz_id, ferrum_authz_db_authz_row_t **row) {
  ferrum_lmdb_t *lmdb = authz_db->lmdb;
  lmdb->root->key.size = snprintf(lmdb->root->key.val, sizeof(lmdb->root->key.val) - 1, "/authz/id/%s", authz_id);
  int32_t result = ferrum_lmdb_get(lmdb, &lmdb->root->key, &lmdb->root->value);
  *row = NULL;
  if (result) {
    if (result == FERRUM_ERR_LMDB) {
      ferrum_log_error("query local authz %s error:%d\n", authz_id, result);
      return FERRUM_ERR_AUTHZ_DB;
    }
    ferrum_log_debug("query local authz %s not found\n", authz_id);
    return FERRUM_SUCCESS; // authz is empty
  }
  if (lmdb->root->value.size) {
    new4(ferrum_authz_db_authz_row_t, authz_row);
    rebrick_malloc2(authz_row->content, lmdb->root->value.size + 1);
    memcpy(authz_row->content, lmdb->root->value.val, lmdb->root->value.size);
    *row = authz_row;
  }
  return FERRUM_SUCCESS;
}