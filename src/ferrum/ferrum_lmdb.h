#ifndef __FERRUM_LMDB_H__
#define __FERRUM_LMDB_H__

#include "ferrum.h"
#include "lmdb.h"

#define FERRUM_LMDB_PATH_LEN 1024
#define FERRUM_LMDB_KEY_LEN 1024
#define FERRUM_LMDB_VALUE_LEN 1048576

typedef struct ferrum_lmdb_entry_key {
  size_t size;
  char val[FERRUM_LMDB_KEY_LEN];
} ferrum_lmdb_entry_key_t;

typedef struct ferrum_lmdb_entry_value {
  size_t size;
  char val[FERRUM_LMDB_VALUE_LEN];
} ferrum_lmdb_entry_value_t;

typedef struct ferrum_lmdb_root {
  base_object();
  char path[1024];
  MDB_env *env;
  MDB_txn *parent_trx;
  int32_t child_count;
  ferrum_lmdb_entry_key_t key;
  ferrum_lmdb_entry_value_t value;
} ferrum_lmdb_root_t;

extern ferrum_lmdb_root_t *lmdb_root;
typedef struct ferrum_lmdb {
  base_object();
  MDB_dbi dbi;
  MDB_txn *trx;
  ferrum_lmdb_root_t *root;
  int32_t mock_error;

} ferrum_lmdb_t;

int32_t ferrum_lmdb_new(ferrum_lmdb_t **lmdb, const char *path, const char *dbname, size_t maxdb, size_t maxsize);
int32_t ferrum_lmdb_put(ferrum_lmdb_t *lmdb, ferrum_lmdb_entry_key_t *key, ferrum_lmdb_entry_value_t *value);
int32_t ferrum_lmdb_get(ferrum_lmdb_t *lmdb, ferrum_lmdb_entry_key_t *key, ferrum_lmdb_entry_value_t *value);
int32_t ferrum_lmdb_del(ferrum_lmdb_t *lmdb, ferrum_lmdb_entry_key_t *key);
int32_t ferrum_lmdb_list_all(ferrum_lmdb_t *lmdb);
int32_t ferrum_lmdb_destroy(ferrum_lmdb_t *lmdb);

#endif