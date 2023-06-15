#include "ferrum_track_db.h"
int32_t ferrum_track_db_new(ferrum_track_db_t **track, ferrum_config_t *config) {
  int32_t result;
  ferrum_lmdb_t *lmdb;
  result = ferrum_lmdb_new(&lmdb, config->track_db_folder, "track", 24, 1073741824);
  if (result)
    return result;
  ferrum_log_info("track lmdb folder:%s\n", config->track_db_folder);

  ferrum_track_db_t *tmp = new1(ferrum_track_db_t);
  if (!tmp) {
    ferrum_log_fatal("malloc problem\n");
    rebrick_kill_current_process(REBRICK_ERR_MALLOC);
  }
  constructor(tmp, ferrum_track_db_t);
  tmp->config = config;
  tmp->lmdb = lmdb;
  *track = tmp;
  return FERRUM_SUCCESS;
}
int32_t ferrum_track_db_destroy(ferrum_track_db_t *track) {
  if (track) {
    if (track->lmdb) {
      ferrum_lmdb_destroy(track->lmdb);
      track->lmdb = NULL;
    }
    rebrick_free(track);
  }
  return FERRUM_SUCCESS;
}

int32_t ferrum_track_db_row_destroy(ferrum_track_db_row_t *row) {
  if (row) {
    if (row->user_id)
      rebrick_free(row->user_id);
    if (row->group_ids)
      rebrick_free(row->group_ids);
    rebrick_free(row);
  }
  return FERRUM_SUCCESS;
}

int32_t ferrum_track_db_get_data(const ferrum_track_db_t *track_db, uint32_t track_id, ferrum_track_db_row_t **row) {

  *row = NULL;
  ferrum_lmdb_t *lmdb = track_db->lmdb;
  lmdb->root->key.size = snprintf(lmdb->root->key.val, sizeof(lmdb->root->key.val) - 1, "/track/id/%" PRIu32 "/data", track_id);
  int32_t result = ferrum_lmdb_get(lmdb, &lmdb->root->key, &lmdb->root->value);
  if (result) {
    if (result == FERRUM_ERR_LMDB) {
      ferrum_log_debug("query local track %u error:%d\n", track_id, result);
      return FERRUM_ERR_TRACK_DB;
    }
    ferrum_log_debug("query local track %u not found\n", track_id);
    // ferrum_lmdb_list_all(lmdb);
    return FERRUM_SUCCESS; // track is empty
  }

  if (!lmdb->root->value.size)
    return FERRUM_SUCCESS;

  char errbuf[200] = {0};
  toml_table_t *conf = toml_parse(lmdb->root->value.val, errbuf, sizeof(errbuf));
  if (!conf) {
    ferrum_log_debug("query local track %u parse error %s\n", track_id, errbuf);
    return FERRUM_ERR_TRACK_DB_PARSE;
  }
  toml_datum_t user_id = toml_string_in(conf, "userId");
  if (!user_id.ok) {
    ferrum_log_debug("query local track %u cannot read user_id %s\n", track_id, errbuf);
    toml_free(conf);
    return FERRUM_ERR_TRACK_DB_PARSE;
  }
  size_t user_id_len = strlen(user_id.u.s);
  new4(ferrum_track_db_row_t, tmp_row);

  if (user_id_len) {
    rebrick_malloc2(tmp_row->user_id, user_id_len + 1);
    memcpy(tmp_row->user_id, user_id.u.s, user_id_len);
  }
  rebrick_free(user_id.u.s);

  toml_datum_t group_ids = toml_string_in(conf, "groupIds");
  if (!group_ids.ok) {
    ferrum_log_debug("query local track %u cannot read group ids %s\n", track_id, errbuf);
    toml_free(conf);
    ferrum_track_db_row_destroy(tmp_row);
    return FERRUM_ERR_TRACK_DB_PARSE;
  }
  size_t group_ids_len = strlen(group_ids.u.s);
  if (group_ids_len) {
    rebrick_malloc2(tmp_row->group_ids, group_ids_len + 1);
    memcpy(tmp_row->group_ids, group_ids.u.s, group_ids_len);
  }
  rebrick_free(group_ids.u.s);
  toml_free(conf);
  *row = tmp_row;
  ferrum_log_debug("query local track %u parsed\n", track_id);
  return FERRUM_SUCCESS;
}

int32_t ferrum_track_db_get_update_time(const ferrum_track_db_t *track_db, uint32_t track_id, int64_t *update_time) {
  ferrum_lmdb_t *lmdb = track_db->lmdb;
  lmdb->root->key.size = snprintf(lmdb->root->key.val, sizeof(lmdb->root->key.val) - 1, "/track/id/%" PRIu32 "/updateTime", track_id);
  int32_t result = ferrum_lmdb_get(lmdb, &lmdb->root->key, &lmdb->root->value);
  *update_time = 0;
  if (result) {
    if (result == FERRUM_ERR_LMDB) {
      ferrum_log_error("query local track %u update time error:%d\n", track_id, result);
      return FERRUM_ERR_TRACK_DB;
    }
    ferrum_log_debug("query local track %u update time not found\n", track_id);
    return FERRUM_SUCCESS; // track is empty
  }
  if (lmdb->root->value.size)
    rebrick_util_to_int64_t(lmdb->root->value.val, update_time);
  ferrum_log_debug("query local track %u  update time %" PRId64 "\n", track_id, *update_time);
  return FERRUM_SUCCESS;
}