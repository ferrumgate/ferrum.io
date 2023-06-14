#ifndef __FERRUM_TRACK_DB_H__
#define __FERRUM_TRACK_DB_H__
#include "ferrum.h"
#include "ferrum_redis.h"
#include "ferrum_config.h"
#include "ferrum_lmdb.h"
#include "../rebrick/lib/toml.h"

typedef struct ferrum_track_db_row {
  char *user_id;
  char *group_ids;
  int64_t update_time;
} ferrum_track_db_row_t;

int32_t ferrum_track_db_row_destroy(ferrum_track_db_row_t *row);

typedef struct ferrum_track_db {
  base_object();
  private_ ferrum_lmdb_t *lmdb;
  private_ ferrum_redis_t *redis;
  private_ ferrum_config_t *config;

} ferrum_track_db_t;

int32_t ferrum_track_db_new(ferrum_track_db_t **track_db, ferrum_config_t *config);
int32_t ferrum_track_db_destroy(ferrum_track_db_t *track_db);
int32_t ferrum_track_db_get_data(const ferrum_track_db_t *track_db, uint32_t track_id, ferrum_track_db_row_t **row);
int32_t ferrum_track_db_get_update_time(const ferrum_track_db_t *track_db, uint32_t track_id, int64_t *update_time);

#endif