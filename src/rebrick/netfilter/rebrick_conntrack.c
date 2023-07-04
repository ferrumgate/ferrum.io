#include "rebrick_conntrack.h"
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

static int gotit = 0; /* yuck */

static int callback(enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data);

int rebrick_conntrack_get(const struct sockaddr *peer_addr, const struct sockaddr *local_addr, int istcp, rebrick_conntrack_t *track) {
  struct nf_conntrack *ct;
  struct nfct_handle *h;

  gotit = 0;

  if ((ct = nfct_new())) {
    nfct_set_attr_u8(ct, ATTR_L4PROTO, istcp ? IPPROTO_TCP : IPPROTO_UDP);

    if (peer_addr->sa_family == AF_INET6) {
      struct sockaddr_in6 *peer = (struct sockaddr_in6 *)peer_addr;
      struct sockaddr_in6 *local = (struct sockaddr_in6 *)local_addr;

      nfct_set_attr_u8(ct, ATTR_L3PROTO, AF_INET6);
      nfct_set_attr(ct, ATTR_IPV6_SRC, peer->sin6_addr.s6_addr);
      nfct_set_attr_u16(ct, ATTR_PORT_SRC, peer->sin6_port);
      nfct_set_attr(ct, ATTR_IPV6_DST, local->sin6_addr.s6_addr);
      nfct_set_attr_u16(ct, ATTR_PORT_DST, local->sin6_port);
    } else {
      struct sockaddr_in *peer = (struct sockaddr_in *)peer_addr;
      struct sockaddr_in *local = (struct sockaddr_in *)local_addr;
      nfct_set_attr_u8(ct, ATTR_L3PROTO, AF_INET);
      nfct_set_attr_u32(ct, ATTR_IPV4_SRC, peer->sin_addr.s_addr);
      nfct_set_attr_u16(ct, ATTR_PORT_SRC, peer->sin_port);
      nfct_set_attr_u32(ct, ATTR_IPV4_DST, local->sin_addr.s_addr);
      nfct_set_attr_u16(ct, ATTR_PORT_DST, local->sin_port);
    }

    if ((h = nfct_open(CONNTRACK, 0))) {
      nfct_callback_register(h, NFCT_T_ALL, callback, (void *)track);
      if (nfct_query(h, NFCT_Q_GET, ct) == -1) {
        static int warned = 0;
        if (!warned) {
          rebrick_log_error("conntrack connection mark retrieval failed: %s\n", strerror(errno));
          warned = 1;
        }
      }
      nfct_close(h);
    }
    nfct_destroy(ct);
  }

  return gotit ? REBRICK_SUCCESS : REBRICK_ERR_NOT_FOUND;
}

static int callback(enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data) {
  rebrick_conntrack_t *ret = cast(data, rebrick_conntrack_t *);
  ret->mark = nfct_get_attr_u32(ct, ATTR_MARK);
  ret->id = nfct_get_attr_u32(ct, ATTR_ID);
  (void)type; /* eliminate warning */
  gotit = 1;

  return NFCT_CB_CONTINUE;
}