#ifndef __REBRICK_RAWSOCKET_H__
#define __REBRICK_RAWSOCKET_H__
#include "rebrick_socket.h"
#include "../common/rebrick_util_net.h"

public_ typedef struct rebrick_rawsocket {
  base_socket();
  int32_t raw_socket;
} rebrick_rawsocket_t;

#define cast_to_rawsocket(x) cast((x), rebrick_rawsocket_t *)

public_ typedef struct rebrick_rawsocket_callbacks {
  base_callbacks();
} rebrick_rawsocket_callbacks_t;

int32_t rebrick_rawsocket_new(rebrick_rawsocket_t **socket,
                              const rebrick_rawsocket_callbacks_t *callbacks);
int32_t rebrick_rawsocket_destroy(rebrick_rawsocket_t *socket);
int32_t rebrick_rawsocket_write_udp(rebrick_rawsocket_t *socket, const rebrick_sockaddr_t *src_addr,
                                    const rebrick_sockaddr_t *dst_addr, uint8_t *buffer, size_t len,
                                    rebrick_clean_func_t clean_func);

#endif //__REBRICK_RAWSOCKET_H__
