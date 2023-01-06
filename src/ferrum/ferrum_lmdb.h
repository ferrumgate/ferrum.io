#ifndef __FERRUM_REDIS_H__
#define __FERRUM_REDIS_H__

#include "ferrum.h"
#include "lmdb.h"

#define FERRUM_LMDB_PATH_LEN 1024
#define FERRUM_LMDB_KEY_LEN 1024
#define FERRUM_LMDB_VALUE_LEN 2048
#define FERRUM_LMDB_ENTRY_LEN 2048

typedef struct ferrum_lmdb_entry {
  size_t size;
  char val[FERRUM_LMDB_VALUE_LEN];
} ferrum_lmdb_entry_t;

typedef struct ferrum_lmdb {
  base_object();
  char path[1024];
  MDB_env *env;
  MDB_dbi dbi;
  MDB_txn *parent_trx;
  MDB_txn *trx;
  int32_t is_readonly;
  struct ferrum_lmdb_entry key;
  struct ferrum_lmdb_entry value;

} ferrum_lmdb_t;

int32_t ferrum_lmdb_new(ferrum_lmdb_t **lmdb, const char *path, const char *dbname, int32_t readonly, size_t maxdb, size_t maxsize);
int32_t ferrum_lmdb_put(ferrum_lmdb_t *lmdb, ferrum_lmdb_entry_t *key, ferrum_lmdb_entry_t *value);
int32_t ferrum_lmdb_get(ferrum_lmdb_t *lmdb, ferrum_lmdb_entry_t *key, ferrum_lmdb_entry_t *value);
int32_t ferrum_lmdb_del(ferrum_lmdb_t *lmdb, ferrum_lmdb_entry_t *key);
int32_t ferrum_lmdb_destroy(ferrum_lmdb_t *lmdb);

#endif