#ifndef __REBRICK_CONNTRACK_H__
#define __REBRICK_CONNTRACK_H__

#include "../socket/rebrick_socket.h"
typedef struct rebrick_conntrack {
  base_object();
  uint32_t mark;
  uint32_t id;
} rebrick_conntrack_t;

int32_t rebrick_conntrack_get(const struct sockaddr *peer, const struct sockaddr *local_addr,
                              int istcp, rebrick_conntrack_t *track);

#endif