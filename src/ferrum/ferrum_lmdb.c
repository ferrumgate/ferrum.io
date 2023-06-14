#include "ferrum_lmdb.h"

ferrum_lmdb_root_t *lmdb_root = NULL;

int32_t ferrum_lmdb_new(ferrum_lmdb_t **lmdb, const char *path, const char *dbname, size_t maxdb, size_t maxsize) {
  int32_t result;

  if (!lmdb_root) {
    int major, minor, patch;
    mdb_version(&major, &minor, &patch);
    ferrum_log_info("lmdb version is %d.%d.%d\n", major, minor, patch);
    ferrum_lmdb_root_t *tmp_root = new1(ferrum_lmdb_root_t);
    if (!tmp_root) {
      ferrum_log_fatal("malloc problem\n");
      rebrick_kill_current_process(REBRICK_ERR_MALLOC);
    }

    constructor(tmp_root, ferrum_lmdb_root_t);
    strncpy(tmp_root->path, path, sizeof(tmp_root->path) - 1);
    // open env
    if ((result = mdb_env_create(&tmp_root->env))) {
      ferrum_log_error("lmdb path %s could not open :%s\n", path, mdb_strerror(result));
      rebrick_free(tmp_root);
      return FERRUM_ERR_LMDB;
    }
    mdb_env_set_maxdbs(tmp_root->env, maxdb ? maxdb : 24);
    mdb_env_set_maxreaders(tmp_root->env, 512);
    mdb_env_set_mapsize(tmp_root->env, maxsize ? maxsize : (size_t)1073741824); // 2GB

    if ((result = mdb_env_open(tmp_root->env, tmp_root->path, MDB_NOTLS, 0664))) {
      ferrum_log_error("lmdb path %s could not open :%s\n", path, mdb_strerror(result));
      mdb_env_close(tmp_root->env);
      rebrick_free(tmp_root);
      return FERRUM_ERR_LMDB;
    }
    lmdb_root = tmp_root;
  }

  ferrum_lmdb_t *tmp = new1(ferrum_lmdb_t);
  if (!tmp) {
    ferrum_log_fatal("malloc problem\n");
    rebrick_kill_current_process(REBRICK_ERR_MALLOC);
  }

  constructor(tmp, ferrum_lmdb_t);
  tmp->root = lmdb_root;
  tmp->root->parent_trx = NULL;
  if ((result = mdb_txn_begin(tmp->root->env, tmp->root->parent_trx, 0, &tmp->trx))) {
    ferrum_log_error("lmdb path %s could not open :%s\n", path, mdb_strerror(result));
    mdb_env_close(tmp->root->env);
    rebrick_free(tmp);
    return FERRUM_ERR_LMDB;
  }
  if ((result = mdb_dbi_open(tmp->trx, dbname, MDB_CREATE, &tmp->dbi))) {
    ferrum_log_error("lmdb path %s could not open :%s\n", path, mdb_strerror(result));
    mdb_txn_abort(tmp->trx);
    rebrick_free(tmp);
    return FERRUM_ERR_LMDB;
  }

  mdb_txn_commit(tmp->trx);
  tmp->root->child_count++;
  *lmdb = tmp;
  return FERRUM_SUCCESS;
}

int32_t ferrum_lmdb_destroy(ferrum_lmdb_t *lmdb) {
  if (lmdb) {
    if (lmdb->dbi) {
      mdb_dbi_close(lmdb->root->env, lmdb->dbi);
      lmdb->root->child_count--;
    }
    if (!lmdb->root->child_count && lmdb->root->env) {
      mdb_env_close(lmdb->root->env);
      lmdb->root->env = NULL;
      rebrick_free(lmdb->root);
      lmdb->root = NULL;
      lmdb_root = NULL;
    }
    rebrick_free(lmdb);
  }
  return FERRUM_SUCCESS;
}

int32_t ferrum_lmdb_put(ferrum_lmdb_t *lmdb, ferrum_lmdb_entry_key_t *key, ferrum_lmdb_entry_value_t *value) {
  int32_t result;
  lmdb->root->parent_trx = NULL;
  if ((result = mdb_txn_begin(lmdb->root->env, lmdb->root->parent_trx, 0, &lmdb->trx))) {
    ferrum_log_error("lmdb trx begin failed with error: %s\n", mdb_strerror(result));

    return FERRUM_ERR_LMDB;
  }
  MDB_val kval = {.mv_size = key->size, .mv_data = key->val};
  MDB_val vval = {.mv_size = value->size, .mv_data = value->val};
  if ((result = mdb_put(lmdb->trx, lmdb->dbi, &kval, &vval, 0))) {
    ferrum_log_error("lmdb put failed with error: %s\n", mdb_strerror(result));
    mdb_txn_abort(lmdb->trx);
    return FERRUM_ERR_LMDB;
  }
  mdb_txn_commit(lmdb->trx);
  return FERRUM_SUCCESS;
}
int32_t ferrum_lmdb_get(ferrum_lmdb_t *lmdb, ferrum_lmdb_entry_key_t *key, ferrum_lmdb_entry_value_t *value) {
  int32_t result;
  lmdb->root->parent_trx = NULL;
  if ((result = mdb_txn_begin(lmdb->root->env, lmdb->root->parent_trx, MDB_RDONLY, &lmdb->trx))) {
    ferrum_log_error("lmdb trx begin failed with error: %s\n", mdb_strerror(result));

    return FERRUM_ERR_LMDB;
  }
  MDB_val kval = {.mv_size = key->size, .mv_data = key->val};
  MDB_val vval;
  if ((result = mdb_get(lmdb->trx, lmdb->dbi, &kval, &vval))) {
    if (result != MDB_NOTFOUND)
      ferrum_log_error("lmdb get failed with error: %s\n", mdb_strerror(result));
    mdb_txn_abort(lmdb->trx);
    return result == MDB_NOTFOUND ? FERRUM_ERR_LMDB_ROW_NOT_FOUND : FERRUM_ERR_LMDB;
  }
  value->size = vval.mv_size;
  memcpy(value->val, vval.mv_data, vval.mv_size > sizeof(value->val) ? sizeof(value->val) - 1 : vval.mv_size);
  value->val[value->size] = 0; // if string than put c style string
  mdb_txn_abort(lmdb->trx);
  return FERRUM_SUCCESS;
}
int32_t ferrum_lmdb_del(ferrum_lmdb_t *lmdb, ferrum_lmdb_entry_key_t *key) {
  int32_t result;
  lmdb->root->parent_trx = NULL;
  if ((result = mdb_txn_begin(lmdb->root->env, lmdb->root->parent_trx, 0, &lmdb->trx))) {
    ferrum_log_error("lmdb trx begin failed with error: %s", mdb_strerror(result));

    return FERRUM_ERR_LMDB;
  }
  MDB_val kval = {.mv_size = key->size, .mv_data = key->val};
  if ((result = mdb_del(lmdb->trx, lmdb->dbi, &kval, NULL))) {
    ferrum_log_error("lmdb get failed with error: %s", mdb_strerror(result));
    mdb_txn_abort(lmdb->trx);
    return result == MDB_NOTFOUND ? FERRUM_ERR_LMDB_ROW_NOT_FOUND : FERRUM_ERR_LMDB;
  }

  mdb_txn_commit(lmdb->trx);
  return FERRUM_SUCCESS;
}

int32_t ferrum_lmdb_list_all(ferrum_lmdb_t *lmdb) {
  int32_t result;
  lmdb->root->parent_trx = NULL;
  if ((result = mdb_txn_begin(lmdb->root->env, lmdb->root->parent_trx, 0, &lmdb->trx))) {
    ferrum_log_error("lmdb trx begin failed with error: %s", mdb_strerror(result));

    return FERRUM_ERR_LMDB;
  }
  MDB_cursor *cursor;
  if ((result = mdb_cursor_open(lmdb->trx, lmdb->dbi, &cursor))) {
    ferrum_log_error("lmdb cursor open failed with error: %s", mdb_strerror(result));
    mdb_txn_abort(lmdb->trx);
    return FERRUM_ERR_LMDB;
  }
  int counter = 0;
  lmdb->root->key.size = 0;
  lmdb->root->key.val[0] = 0;
  MDB_val kval = {.mv_size = lmdb->root->key.size, .mv_data = lmdb->root->key.val};
  MDB_val vval;
  while (1) {

    if ((result = mdb_cursor_get(cursor, &kval, &vval, counter ? MDB_NEXT : MDB_FIRST))) {
      ferrum_log_error("lmdb get failed with error: %s\n", mdb_strerror(result));
      break;
    } else {
      lmdb->root->key.size = kval.mv_size;
      memcpy(lmdb->root->key.val, kval.mv_data, kval.mv_size);
      lmdb->root->key.val[lmdb->root->key.size] = 0;

      lmdb->root->value.size = vval.mv_size;
      memcpy(lmdb->root->value.val, vval.mv_data, vval.mv_size > sizeof(lmdb->root->value.val) ? sizeof(lmdb->root->value.val) - 1 : vval.mv_size);
      lmdb->root->value.val[lmdb->root->value.size] = 0; // if string than put c style string
      ferrum_log_info("%s ==> %s\n", lmdb->root->key.val, lmdb->root->value.val);
    }
    counter++;
  }
  mdb_cursor_close(cursor);
  mdb_txn_abort(lmdb->trx);
  return FERRUM_SUCCESS;
}