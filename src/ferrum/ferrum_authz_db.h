#ifndef __FERRUM_AUTHZ_DB_H__
#define __FERRUM_AUTHZ_DB_H__
#include "ferrum.h"
#include "ferrum_redis.h"
#include "ferrum_config.h"
#include "ferrum_lmdb.h"
#include "../rebrick/lib/toml.h"

struct authz_service_user_data {
  char *user_or_group_ids;
  char *authz_id;
};

typedef struct ferrum_authz_db_service_user_row {
  struct authz_service_user_data *rows;
  size_t rows_len;
  size_t rows_len_real;
  int64_t update_time;
} ferrum_authz_db_service_user_row_t;

int32_t ferrum_authz_db_service_user_row_destroy(ferrum_authz_db_service_user_row_t *row);

typedef struct ferrum_authz_db {
  base_object();
  private_ ferrum_lmdb_t *lmdb;
  private_ ferrum_redis_t *redis;
  private_ ferrum_config_t *config;

} ferrum_authz_db_t;

int32_t ferrum_authz_db_new(ferrum_authz_db_t **authz_db, ferrum_config_t *config);
int32_t ferrum_authz_db_destroy(ferrum_authz_db_t *authz_db);
int32_t ferrum_authz_db_get_service_user_data(const ferrum_authz_db_t *authz_db, const char *service_id, ferrum_authz_db_service_user_row_t **row);
int32_t ferrum_authz_db_get_service_user_update_time(const ferrum_authz_db_t *authz_db, const char *service_id, int64_t *update_time);

typedef struct ferrum_authz_db_authz_row {
  char *content;
  int64_t update_time;
} ferrum_authz_db_authz_row_t;

int32_t ferrum_authz_db_authz_row_destroy(ferrum_authz_db_authz_row_t *row);

int32_t ferrum_authz_db_get_authz_data(const ferrum_authz_db_t *authz_db, const char *authz_id, ferrum_authz_db_authz_row_t **row);
int32_t ferrum_authz_db_get_authz_update_time(const ferrum_authz_db_t *authz_db, const char *authz_id, int64_t *update_time);

#endif