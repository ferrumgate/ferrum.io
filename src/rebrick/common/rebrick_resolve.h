#ifndef __REBRICK_RESOLVE_H__
#define __REBRICK_RESOLVE_H__

#include "rebrick_common.h"
#include "rebrick_log.h"

typedef enum rebrick_resolve_type {
  A,
  AAAA
} rebrick_resolve_type_t;

typedef void (*on_resolve_callback_t)(const char *domain, int32_t type, rebrick_sockaddr_t addr);
typedef void (*on_resolve_error_callback_t)(const char *domain, int32_t type, int32_t error);
int32_t rebrick_resolve(const char *domain, rebrick_resolve_type_t type, on_resolve_callback_t on_resolve, on_resolve_error_callback_t on_error);

int32_t rebrick_resolve_sync(const char *domain, rebrick_resolve_type_t type,
                             rebrick_sockaddr_t **addr, size_t *len);

#endif