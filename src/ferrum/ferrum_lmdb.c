#include "ferrum_lmdb.h"
int32_t ferrum_lmdb_new(ferrum_lmdb_t **lmdb, const char *path, const char *dbname, size_t maxdb, size_t maxsize) {
  int32_t result;
  ferrum_lmdb_t *tmp = new1(ferrum_lmdb_t);
  if (!tmp) {
    ferrum_log_fatal("malloc problem\n");
    rebrick_kill_current_process(REBRICK_ERR_MALLOC);
  }
  int major, minor, patch;
  mdb_version(&major, &minor, &patch);
  ferrum_log_info("lmdb version is %d.%d.%d\n", major, minor, patch);
  constructor(tmp, ferrum_lmdb_t);
  strncpy(tmp->path, path, sizeof(tmp->path) - 1);
  // open env
  if ((result = mdb_env_create(&tmp->env))) {
    ferrum_log_error("lmdb path %s could not open :%s", path, mdb_strerror(result));
    rebrick_free(tmp);
    return FERRUM_ERR_LMDB;
  }
  mdb_env_set_maxdbs(tmp->env, maxdb ? maxdb : 3);
  mdb_env_set_mapsize(tmp->env, maxsize ? maxsize : (size_t)1073741824); // 2GB

  if ((result = mdb_env_open(tmp->env, tmp->path, MDB_NOTLS, 0664))) {
    ferrum_log_error("lmdb path %s could not open :%s", path, mdb_strerror(result));
    mdb_env_close(tmp->env);
    rebrick_free(tmp);
    return FERRUM_ERR_LMDB;
  }

  tmp->parent_trx = NULL;
  if ((result = mdb_txn_begin(tmp->env, tmp->parent_trx, 0, &tmp->trx))) {
    ferrum_log_error("lmdb path %s could not open :%s", path, mdb_strerror(result));
    mdb_env_close(tmp->env);
    rebrick_free(tmp);
    return FERRUM_ERR_LMDB;
  }
  if ((result = mdb_dbi_open(tmp->trx, dbname, MDB_CREATE, &tmp->dbi))) {
    ferrum_log_error("lmdb path %s could not open :%s", path, mdb_strerror(result));
    mdb_txn_abort(tmp->trx);
    mdb_env_close(tmp->env);
    rebrick_free(tmp);
    return FERRUM_ERR_LMDB;
  }

  mdb_txn_commit(tmp->trx);

  *lmdb = tmp;
  return FERRUM_SUCCESS;
}

int32_t ferrum_lmdb_destroy(ferrum_lmdb_t *lmdb) {
  if (lmdb) {
    if (lmdb->dbi) {
      mdb_dbi_close(lmdb->env, lmdb->dbi);
    }
    if (lmdb->env) {
      mdb_env_close(lmdb->env);
      lmdb->env = NULL;
    }
    rebrick_free(lmdb);
  }
  return FERRUM_SUCCESS;
}

int32_t ferrum_lmdb_put(ferrum_lmdb_t *lmdb, ferrum_lmdb_entry_t *key, ferrum_lmdb_entry_t *value) {
  int32_t result;
  lmdb->parent_trx = NULL;
  if ((result = mdb_txn_begin(lmdb->env, lmdb->parent_trx, 0, &lmdb->trx))) {
    ferrum_log_error("lmdb trx begin failed with error: %s", mdb_strerror(result));

    return FERRUM_ERR_LMDB;
  }
  MDB_val kval = {.mv_size = key->size, .mv_data = key->val};
  MDB_val vval = {.mv_size = value->size, .mv_data = value->val};
  if ((result = mdb_put(lmdb->trx, lmdb->dbi, &kval, &vval, 0))) {
    ferrum_log_error("lmdb put failed with error: %s", mdb_strerror(result));
    mdb_txn_abort(lmdb->trx);
    return FERRUM_ERR_LMDB;
  }
  mdb_txn_commit(lmdb->trx);
  return FERRUM_SUCCESS;
}
int32_t ferrum_lmdb_get(ferrum_lmdb_t *lmdb, ferrum_lmdb_entry_t *key, ferrum_lmdb_entry_t *value) {
  int32_t result;
  lmdb->parent_trx = NULL;
  if ((result = mdb_txn_begin(lmdb->env, lmdb->parent_trx, MDB_RDONLY, &lmdb->trx))) {
    ferrum_log_error("lmdb trx begin failed with error: %s", mdb_strerror(result));

    return FERRUM_ERR_LMDB;
  }
  MDB_val kval = {.mv_size = key->size, .mv_data = key->val};
  MDB_val vval;
  if ((result = mdb_get(lmdb->trx, lmdb->dbi, &kval, &vval))) {
    if (result != MDB_NOTFOUND)
      ferrum_log_error("lmdb get failed with error: %s", mdb_strerror(result));
    mdb_txn_abort(lmdb->trx);
    return result == MDB_NOTFOUND ? FERRUM_ERR_LMDB_ROW_NOT_FOUND : FERRUM_ERR_LMDB;
  }
  value->size = vval.mv_size;
  memcpy(value->val, vval.mv_data, vval.mv_size > sizeof(value->val) ? sizeof(value->val) - 1 : vval.mv_size);
  value->val[value->size + 1] = 0; // if string than put c style string
  mdb_txn_abort(lmdb->trx);
  return FERRUM_SUCCESS;
}
int32_t ferrum_lmdb_del(ferrum_lmdb_t *lmdb, ferrum_lmdb_entry_t *key) {
  int32_t result;
  lmdb->parent_trx = NULL;
  if ((result = mdb_txn_begin(lmdb->env, lmdb->parent_trx, 0, &lmdb->trx))) {
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