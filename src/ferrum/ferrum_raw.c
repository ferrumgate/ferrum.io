#include "ferrum_raw.h"

static uint64_t socket_pair_id = 0;

static void free_memory(void *data) {
  if (data)
    rebrick_free(data);
}

static void on_tcp_destination_close(rebrick_socket_t *socket, void *callbackdata) {
  unused(socket);
  unused(callbackdata);
  ferrum_raw_t *raw = cast(callbackdata, ferrum_raw_t *);
  raw->metrics.connected_clients--;
}
static void on_tcp_destination_connect(rebrick_socket_t *socket, void *callbackdata) {
  unused(callbackdata);
  unused(socket);
  rebrick_tcpsocket_t *tcp = cast_to_tcpsocket(socket);
  ferrum_raw_t *raw = cast(callbackdata, ferrum_raw_t *);
  ferrum_raw_socket_pair_t *pair = NULL;
  HASH_FIND(hh, raw->socket_pairs, &tcp->id1, sizeof(uint64_t), pair);
  if (pair) {
    if (pair->source.tcp)
      rebrick_tcpsocket_start_reading(pair->source.tcp);
  }
}

static void on_tcp_destination_error(rebrick_socket_t *socket, void *callbackdata, int32_t error) {
  unused(socket);
  unused(callbackdata);
  unused(error);
  rebrick_tcpsocket_t *tcp = cast_to_tcpsocket(socket);
  ferrum_raw_t *raw = cast(callbackdata, ferrum_raw_t *);

  // if (error == (REBRICK_ERR_UV + UV_EOF) || error == (REBRICK_ERR_UV + UV_ECONNRESET)) { // client connection closed
  ferrum_raw_socket_pair_t *pair = NULL;
  HASH_FIND(hh, raw->socket_pairs, &tcp->id1, sizeof(uint64_t), pair);
  rebrick_log_info("destination tcp socket closed\n");
  if (pair) {
    HASH_DEL(raw->socket_pairs, pair);
    rebrick_tcpsocket_destroy(pair->source.tcp);
    rebrick_free(pair);
  }
  rebrick_tcpsocket_destroy(tcp);
  /* } else {
    int32_t uv_err = HAS_UV_ERR(error) ? UV_ERR(error) : 0;
    rebrick_log_error("destination socket error occured on socket %s\n", uv_strerror(uv_err));
  } */
}

void on_tcp_destination_read(rebrick_socket_t *socket, void *callback_data,
                             const struct sockaddr *addr, const uint8_t *buffer, ssize_t len) {
  unused(socket);
  unused(callback_data);
  unused(addr);
  unused(buffer);
  unused(len);
  rebrick_tcpsocket_t *tcp = cast_to_tcpsocket(socket);
  ferrum_raw_t *raw = cast(callback_data, ferrum_raw_t *);
  ferrum_raw_socket_pair_t *pair = NULL;
  HASH_FIND(hh, raw->socket_pairs, &tcp->id1, sizeof(uint64_t), pair);
  if (pair) {
    uint8_t *buf = rebrick_malloc(len);
    if_is_null_then_die(buf, "malloc problem\n");
    memcpy(buf, buffer, len);
    new2(rebrick_clean_func_t, clean_func);
    clean_func.func = free_memory;
    clean_func.ptr = buf;
    int32_t result = rebrick_tcpsocket_write(pair->source.tcp, buf, len, clean_func);
    if (result) {
      rebrick_free(buf);
    }
  }
}
void on_tcp_destination_write(rebrick_socket_t *socket, void *callback_data, void *source) {
  unused(socket);
  unused(callback_data);
  unused(source);
}

static void on_tcp_client_connect(rebrick_socket_t *server_socket, void *callbackdata,
                                  const struct sockaddr *addr, void *client_handle) {
  unused(callbackdata);
  unused(addr);

  unused(client_handle);
  unused(socket);

  rebrick_sockaddr_t client_addr;
  int32_t result = rebrick_util_addr_to_rebrick_addr(addr, &client_addr);
  if (result) {
    rebrick_log_error("sockaddr to rebrick_sockaddr failed with error:%d\n", result);
    rebrick_tcpsocket_destroy2(cast_to_tcpsocket(client_handle));
  }

  char ip_str[REBRICK_IP_STR_LEN] = {0};
  char port_str[REBRICK_PORT_STR_LEN] = {0};
  result = rebrick_util_addr_to_ip_string(&client_addr, ip_str);
  if (result) {
    rebrick_log_error("sockaddr to rebrick_sockaddr failed with error:%d\n", result);
    rebrick_tcpsocket_destroy2(cast_to_tcpsocket(client_handle));
  }

  result = rebrick_util_addr_to_port_string(&client_addr, port_str);
  if (result) {
    rebrick_log_error("sockaddr to rebrick_sockaddr failed with error:%d\n", result);
    rebrick_tcpsocket_destroy2(cast_to_tcpsocket(client_handle));
  }

  ferrum_raw_t *raw = cast(callbackdata, ferrum_raw_t *);

  new2(rebrick_conntrack_t, conntrack);
  result = raw->conntrack_get(addr, &server_socket->bind_addr.base, TRUE, &conntrack);
  if (result) {
    rebrick_log_error("no conntrack found for ip %s:%s\n", ip_str, port_str);
    // TODO event log
    rebrick_tcpsocket_destroy2(cast_to_tcpsocket(client_handle));
    return;
  }
  // execute policy, if fails close socket
  new2(ferrum_policy_result_t, presult);
  result = ferrum_policy_execute(raw->policy, conntrack.mark, &presult);
  if (result) {
    rebrick_log_error("policy execute failed with error:%d\n", result);
    // TODO event log
    rebrick_tcpsocket_destroy2(cast_to_tcpsocket(client_handle));
    return;
  }
  if (presult.isBlocked) {
    rebrick_log_debug("tcp connection blocked %s:%s\n", ip_str, port_str);
    // TODO event log
    rebrick_tcpsocket_destroy2(cast_to_tcpsocket(client_handle));
    return;
  }
  // TODO event log, policy is allowed, log and continue
  rebrick_tcpsocket_t *client = cast_to_tcpsocket(client_handle);
  rebrick_tcpsocket_t *destination;
  new2(rebrick_tcpsocket_callbacks_t, destination_callback);
  destination_callback.callback_data = raw;
  destination_callback.on_close = on_tcp_destination_close;
  destination_callback.on_connect = on_tcp_destination_connect;
  destination_callback.on_error = on_tcp_destination_error;
  destination_callback.on_read = on_tcp_destination_read;
  destination_callback.on_write = on_tcp_destination_write;
  char test[128] = {0};
  rebrick_util_addr_to_string(&raw->listen.tcp_destination_addr, test);
  result = rebrick_tcpsocket_new(&destination, NULL, &raw->listen.tcp_destination_addr, 0, &destination_callback);
  if (result) {
    rebrick_log_error("creating destination socket failed %d\n", result);
    rebrick_tcpsocket_destroy2(cast_to_tcpsocket(client_handle));
    return;
  }
  client->id1 = socket_pair_id;
  destination->id1 = socket_pair_id;
  ferrum_raw_socket_pair_t *pair = new1(ferrum_raw_socket_pair_t);
  constructor(pair, ferrum_raw_socket_pair_t);
  pair->source.tcp = client;
  pair->destination.tcp = destination;
  pair->key = socket_pair_id;
  socket_pair_id++;
  HASH_ADD(hh, raw->socket_pairs, key, sizeof(uint64_t), pair);
}

static void on_tcp_error(rebrick_socket_t *socket, void *callbackdata, int32_t error) {
  unused(socket);
  unused(callbackdata);
  unused(error);
  rebrick_tcpsocket_t *tcp = cast_to_tcpsocket(socket);
  ferrum_raw_t *raw = cast(callbackdata, ferrum_raw_t *);
  if (tcp->is_server) {
    rebrick_log_error("server socket error occured on socket %d\n", error);
  } else {
    rebrick_log_error("client socket error %d\n", error);
    // if (error == (REBRICK_ERR_UV + UV_EOF) || error == (REBRICK_ERR_UV + UV_ECONNRESET)) { // client connection closed
    ferrum_raw_socket_pair_t *pair = NULL;
    HASH_FIND(hh, raw->socket_pairs, &tcp->id1, sizeof(uint64_t), pair);
    rebrick_log_info("client tcp socket closed\n");
    if (pair) {
      rebrick_log_info("delete tcp socket pair\n");
      HASH_DEL(raw->socket_pairs, pair);
      rebrick_tcpsocket_destroy(pair->destination.tcp);
      rebrick_free(pair);
    }
    rebrick_tcpsocket_destroy(tcp);
    /*  } else {
       int32_t uv_err = HAS_UV_ERR(error) ? UV_ERR(error) : 0;
       rebrick_log_error("client socket error occured on socket %s\n", uv_strerror(uv_err));
     } */
  }
}
static void on_tcp_server_close(rebrick_socket_t *socket, void *callbackdata) {
  unused(socket);
  unused(callbackdata);
  ferrum_raw_t *raw = cast(callbackdata, ferrum_raw_t *);
  ferrum_raw_socket_pair_t *el, *tmp;
  HASH_ITER(hh, raw->socket_pairs, el, tmp) {
    HASH_DEL(raw->socket_pairs, el);
    rebrick_tcpsocket_destroy(el->source.tcp);
    rebrick_tcpsocket_destroy(el->destination.tcp);
    rebrick_free(el);
  }
  rebrick_free(raw);
}

void on_tcp_client_read(rebrick_socket_t *socket, void *callback_data,
                        const struct sockaddr *addr, const uint8_t *buffer, ssize_t len) {
  unused(socket);
  unused(callback_data);
  unused(addr);
  unused(buffer);
  unused(len);
  rebrick_tcpsocket_t *tcp = cast_to_tcpsocket(socket);
  ferrum_raw_t *raw = cast(callback_data, ferrum_raw_t *);
  ferrum_raw_socket_pair_t *pair = NULL;
  HASH_FIND(hh, raw->socket_pairs, &tcp->id1, sizeof(uint64_t), pair);
  if (pair) {
    uint8_t *buf = rebrick_malloc(len);
    if_is_null_then_die(buf, "malloc problem\n");
    memcpy(buf, buffer, len);
    new2(rebrick_clean_func_t, clean_func);
    clean_func.func = free_memory;
    clean_func.ptr = buf;
    int32_t result = rebrick_tcpsocket_write(pair->destination.tcp, buf, len, clean_func);
    if (result) {
      rebrick_free(buf);
    }
  }
}
void on_tcp_client_write(rebrick_socket_t *socket, void *callback_data, void *source) {
  unused(socket);
  unused(callback_data);
  unused(source);
}

static void on_tcp_client_close(rebrick_socket_t *socket, void *callbackdata) {
  unused(socket);
  unused(callbackdata);
  ferrum_raw_t *raw = cast(callbackdata, ferrum_raw_t *);
  raw->metrics.connected_clients--;
}

int32_t ferrum_raw_new(ferrum_raw_t **raw, const ferrum_config_t *config,
                       const ferrum_policy_t *policy, rebrick_conntrack_get_func_t conntrack) {

  ferrum_raw_t *tmp = new1(ferrum_raw_t);
  constructor(tmp, ferrum_raw_t);
  int32_t result;

  if (config->raw.listen_tcp_addr_str[0]) {
    memcpy(&tmp->listen.tcp_listening_addr, &config->raw.listen_tcp_addr, sizeof(rebrick_sockaddr_t));
    memcpy(&tmp->listen.tcp_destination_addr, &config->raw.dest_tcp_addr, sizeof(rebrick_sockaddr_t));
    new2(rebrick_tcpsocket_callbacks_t, listen_callback);
    listen_callback.callback_data = tmp;
    listen_callback.on_client_close = on_tcp_client_close;
    listen_callback.on_client_connect = on_tcp_client_connect;
    listen_callback.on_error = on_tcp_error;
    listen_callback.on_close = on_tcp_server_close;
    listen_callback.on_read = on_tcp_client_read;
    listen_callback.on_write = on_tcp_client_write;

    result = rebrick_tcpsocket_new2(&tmp->listen.tcp, &tmp->listen.tcp_listening_addr, NULL, 100, &listen_callback, FALSE);
    if (result) {
      ferrum_log_fatal("listening socket failed at %s\n", config->raw.listen_tcp_addr_str);
      ferrum_raw_destroy(tmp);
      return result;
    }
    rebrick_log_info("tcp server started at %s\n", config->raw.listen_tcp_addr_str);
  }
  tmp->config = config;
  tmp->conntrack_get = conntrack;
  tmp->policy = policy;

  *raw = tmp;

  return FERRUM_SUCCESS;
}
int32_t ferrum_raw_destroy(ferrum_raw_t *raw) {
  if (raw) {
    if (raw->listen.tcp)
      rebrick_tcpsocket_destroy(raw->listen.tcp);
    if (raw->listen.udp)
      rebrick_udpsocket_destroy(raw->listen.udp);
  }
  return FERRUM_SUCCESS;
}