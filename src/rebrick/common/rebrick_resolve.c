#include "rebrick_resolve.h"

struct addrinfo;

typedef struct resolver {
  base_object();
  char domain[REBRICK_DOMAIN_LEN];
  rebrick_resolve_type_t type;
  on_resolve_callback_t on_resolve;
  on_resolve_error_callback_t on_error;
  void *data;
} rebrick_resolver_t;

static void getaddrinfo_cb(uv_getaddrinfo_t *handle, int status, struct addrinfo *response) {
  rebrick_resolver_t *resolver = NULL;

  resolver = cast(handle->data, rebrick_resolver_t *);
  if (status < 0) {

    if (resolver) {
      if (resolver->on_error)
        resolver->on_error(resolver->domain, resolver->type, REBRICK_ERR_UV + status, resolver->data);
      rebrick_log_error("resolve failed for %s %s \n", resolver->domain, uv_strerror(status));
      rebrick_free(resolver);
    }
    rebrick_free(handle);
    return;
  }

  if (resolver) {
    if (resolver->on_resolve) {
      rebrick_sockaddr_t addr;
      if (response->ai_family == AF_INET) {
        struct sockaddr_in *in4 = cast(response->ai_addr, struct sockaddr_in *);
        memcpy(&addr.v4.sin_addr, &in4->sin_addr, 4);
        addr.v4.sin_family = AF_INET;
        if (resolver->on_resolve)
          resolver->on_resolve(resolver->domain, resolver->type, addr, resolver->data);
      } else if (response->ai_family == AF_INET6) {
        struct sockaddr_in6 *in6 = cast(response->ai_addr, struct sockaddr_in6 *);
        memcpy(&addr.v6.sin6_addr, &in6->sin6_addr, 16);
        addr.v6.sin6_family = AF_INET6;
        if (resolver->on_resolve)
          resolver->on_resolve(resolver->domain, resolver->type, addr, resolver->data);
      } else {
        if (resolver->on_error)
          resolver->on_error(resolver->domain, resolver->type, REBRICK_ERR_UNSUPPORT_IPFAMILY, resolver->data);
      }
    }
    rebrick_free(resolver);
  }

  rebrick_free(handle);
  uv_freeaddrinfo(response);
}

int32_t rebrick_resolve(const char *domain, rebrick_resolve_type_t type, on_resolve_callback_t on_resolve, on_resolve_error_callback_t on_error, void *data) {

  rebrick_log_info("resolving %s with type:%d\n", domain, type);
  uv_getaddrinfo_t *handle = new1(uv_getaddrinfo_t);
  fill_zero(handle, sizeof(uv_getaddrinfo_t));

  rebrick_resolver_t *resolver = new1(rebrick_resolver_t);
  constructor(resolver, rebrick_resolver_t);
  strncpy(resolver->domain, domain, REBRICK_DOMAIN_LEN - 1);
  resolver->type = type;
  resolver->on_error = on_error;
  resolver->on_resolve = on_resolve;
  resolver->data = data;

  handle->data = resolver;
  struct addrinfo hints;
  fill_zero(&hints, sizeof(hints));
  hints.ai_family = type == A ? AF_INET : AF_INET6;
  hints.ai_flags |= AI_CANONNAME;
  hints.ai_socktype = SOCK_STREAM;
  int32_t result = uv_getaddrinfo(uv_default_loop(), handle, getaddrinfo_cb, domain, "80", &hints);
  if (result) {
    return REBRICK_ERR_UV + result;
  }

  return REBRICK_SUCCESS;
}

int32_t rebrick_resolve_sync(const char *domain, rebrick_resolve_type_t type,
                             rebrick_sockaddr_t **addr, size_t *len) {

  *len = 0;
  *addr = NULL;
  rebrick_log_info("resolving %s\n", domain);
  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = type == A ? AF_INET : AF_INET6;
  hints.ai_flags |= AI_CANONNAME;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = IPPROTO_UDP;
  struct addrinfo *result, *tmp;
  int res = getaddrinfo(domain, NULL, &hints, &result);
  if (res) {
    // rebrick_log_error("%s resolve failed:%s for type:%s\n", type == A ? "A" : "AAAA", domain, gai_strerror(res));
    return REBRICK_ERR_RESOLV;
  }
  size_t tcounter = 0;
  for (tmp = result; tmp != NULL; tmp = tmp->ai_next)
    tcounter++;
  rebrick_sockaddr_t *ptraddr = new_array(rebrick_sockaddr_t, tcounter);
  size_t counter = 0;
  for (tmp = result; tmp != NULL; tmp = tmp->ai_next) {
    rebrick_util_addr_to_rebrick_addr(tmp->ai_addr, ptraddr + (counter++));
  }
  freeaddrinfo(result);
  *addr = ptraddr;
  *len = tcounter;
  return REBRICK_SUCCESS;
}