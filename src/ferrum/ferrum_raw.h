#ifndef __FERRUM_RAW_H__
#define __FERRUM_RAW_H__
#include "ferrum.h"
#include "ferrum_config.h"
#include "ferrum_redis.h"
typedef struct ferrum_raw {
  base_object();

  private_ ferrum_config_t *config;

  struct {
    private_ rebrick_tcpsocket_t *tcp;
    private_ rebrick_udpsocket_t *udp;
  } listen;

} ferrum_raw_t;

int32_t ferrum_raw_new(ferrum_raw_t **raw, const ferrum_config_t *config);
int32_t ferrum_raw_destroy(ferrum_raw_t *raw);

#endif