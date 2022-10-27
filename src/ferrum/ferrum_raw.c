#include "ferrum_raw.h"

int32_t ferrum_raw_new(ferrum_raw_t **raw, const ferrum_config_t *config) {
  ferrum_raw_t *tmp = new1(ferrum_raw_t);
  constructor(tmp, ferrum_raw_t);

  if (config->raw.dest_tcp_port) {
  }

  *raw = tmp;

  return FERRUM_SUCCESS;
}
int32_t ferrum_raw_destroy(ferrum_raw_t *raw) {
  if (raw) {
    rebrick_free(raw);
  }
  return FERRUM_SUCCESS;
}