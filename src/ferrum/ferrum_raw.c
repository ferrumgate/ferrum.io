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
  raw->socket_count--;
  if (!raw->socket_count && raw->is_destroy_started)
    rebrick_free(raw);
}
static void on_tcp_destination_connect(rebrick_socket_t *socket, void *callbackdata) {
  unused(callbackdata);
  unused(socket);
  rebrick_tcpsocket_t *tcp = cast_to_tcpsocket(socket);
  ferrum_raw_t *raw = cast(callbackdata, ferrum_raw_t *);
  ferrum_raw_tcpsocket_pair_t *pair = NULL;
  HASH_FIND(hh, raw->tcp_socket_pairs, &tcp->id1, sizeof(uint64_t), pair);
  if (pair) {
    if (pair->source)
      rebrick_tcpsocket_start_reading(pair->source);
  }
}

static void on_tcp_destination_error(rebrick_socket_t *socket, void *callbackdata, int32_t error) {
  unused(socket);
  unused(callbackdata);
  unused(error);
  rebrick_tcpsocket_t *tcp = cast_to_tcpsocket(socket);
  ferrum_raw_t *raw = cast(callbackdata, ferrum_raw_t *);

  // if (error == (REBRICK_ERR_UV + UV_EOF) || error == (REBRICK_ERR_UV + UV_ECONNRESET)) { // client connection closed
  ferrum_raw_tcpsocket_pair_t *pair = NULL;
  HASH_FIND(hh, raw->tcp_socket_pairs, &tcp->id1, sizeof(uint64_t), pair);
  rebrick_log_info("destination tcp socket closed\n");
  if (pair) {
    HASH_DEL(raw->tcp_socket_pairs, pair);
    rebrick_tcpsocket_destroy(pair->source);
    rebrick_free(pair);
  }
  rebrick_tcpsocket_destroy(tcp);
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
  ferrum_raw_tcpsocket_pair_t *pair = NULL;
  HASH_FIND(hh, raw->tcp_socket_pairs, &tcp->id1, sizeof(uint64_t), pair);
  if (pair) {
    uint8_t *buf = rebrick_malloc(len);
    if_is_null_then_die(buf, "malloc problem\n");
    memcpy(buf, buffer, len);
    new2(rebrick_clean_func_t, clean_func);
    clean_func.func = free_memory;
    clean_func.ptr = buf;
    int32_t result = rebrick_tcpsocket_write(pair->source, buf, len, clean_func);
    if (result) {
      rebrick_free(buf);
    }
    if (tcp->is_reading_started) {
      size_t buflen = 0;
      result = rebrick_tcpsocket_write_buffer_size(pair->source, &buflen);
      if (result) // error
        return;
      if (buflen > raw->config->socket_max_write_buf_size) { // so much data in destination buffer
        rebrick_tcpsocket_stop_reading(tcp);
      }
    }
  }
  // else not found ??????
}
void on_tcp_destination_write(rebrick_socket_t *socket, void *callback_data, void *source) {
  unused(socket);
  unused(callback_data);
  unused(source);
}

static void write_activity_log(const ferrum_syslog_t *syslog, const ferrum_policy_result_t *result, const rebrick_sockaddr_t *client_addr) {

  unused(client_addr);
  char log[1024] = {0};
  size_t len = snprintf(log, 1023, "/%" PRId64 "/%d/%d/%d/%s/%s/%s/%s/%s/%s/%s", rebrick_util_micro_time(), result->client_id, result->is_dropped, result->why,
                        syslog->config->gateway_id, syslog->config->service_id, result->policy_id, result->user_id, result->tun_id,
                        result->client_ip, result->client_port);
  ferrum_syslog_write(syslog, cast_to_uint8ptr(log), len);
}

static void on_tcp_client_connect(rebrick_socket_t *server_socket, void *callbackdata,
                                  const struct sockaddr *addr, void *client_handle) {
  unused(callbackdata);
  unused(addr);

  unused(client_handle);
  unused(socket);
  ferrum_raw_t *raw = cast(callbackdata, ferrum_raw_t *);
  raw->socket_count++;
  raw->metrics.connected_clients++;
  rebrick_sockaddr_t client_addr;
  fill_zero(&client_addr, sizeof(rebrick_sockaddr_t));
  int32_t result = rebrick_util_addr_to_rebrick_addr(addr, &client_addr);
  if (result) {
    rebrick_log_error("sockaddr to rebrick_sockaddr failed with error:%d\n", result);
    rebrick_tcpsocket_destroy(cast_to_tcpsocket(client_handle));
    return;
  }

  char ip_str[REBRICK_IP_STR_LEN] = {0};
  char port_str[REBRICK_PORT_STR_LEN] = {0};
  result = rebrick_util_addr_to_ip_string(&client_addr, ip_str);
  if (result) {
    rebrick_log_error("sockaddr to rebrick_sockaddr failed with error:%d\n", result);
    rebrick_tcpsocket_destroy(cast_to_tcpsocket(client_handle));
    return;
  }

  result = rebrick_util_addr_to_port_string(&client_addr, port_str);
  if (result) {
    rebrick_log_error("sockaddr to rebrick_sockaddr failed with error:%d\n", result);
    rebrick_tcpsocket_destroy(cast_to_tcpsocket(client_handle));
    return;
  }

  new2(rebrick_conntrack_t, conntrack);
  new2(ferrum_policy_result_t, presult);
  strncpy(presult.client_ip, ip_str, sizeof(presult.client_ip) - 1);
  strncpy(presult.client_port, port_str, sizeof(presult.client_port) - 1);

  result = raw->conntrack_get(addr, &server_socket->bind_addr.base, TRUE, &conntrack);
  if (result) {
    rebrick_log_error("no conntrack found for ip %s:%s\n", ip_str, port_str);
    presult.is_dropped = TRUE;
    presult.why = FERRUM_POLICY_CLIENT_NOT_FOUND;
    write_activity_log(raw->syslog, &presult, &client_addr);
    rebrick_tcpsocket_destroy(cast_to_tcpsocket(client_handle));
    return;
  }
  // execute policy, if fails close socket

  result = ferrum_policy_execute(raw->policy, conntrack.mark, &presult);
  if (result) {
    rebrick_log_error("policy execute failed with error:%d\n", result);
    write_activity_log(raw->syslog, &presult, &client_addr);
    rebrick_tcpsocket_destroy(cast_to_tcpsocket(client_handle));
    return;
  }
  if (presult.is_dropped) {
    rebrick_log_debug("tcp connection blocked %s:%s\n", ip_str, port_str);
    write_activity_log(raw->syslog, &presult, &client_addr);
    rebrick_tcpsocket_destroy(cast_to_tcpsocket(client_handle));
    return;
  }
  // event log, policy is allowed, log and continue
  write_activity_log(raw->syslog, &presult, &client_addr);
  rebrick_tcpsocket_t *client = cast_to_tcpsocket(client_handle);
  rebrick_tcpsocket_t *destination;
  new2(rebrick_tcpsocket_callbacks_t, destination_callback);
  destination_callback.callback_data = raw;
  destination_callback.on_close = on_tcp_destination_close;
  destination_callback.on_connect = on_tcp_destination_connect;
  destination_callback.on_error = on_tcp_destination_error;
  destination_callback.on_read = on_tcp_destination_read;
  destination_callback.on_write = on_tcp_destination_write;

  result = rebrick_tcpsocket_new(&destination, NULL, &raw->listen.tcp_destination_addr, 0, &destination_callback);
  if (result) {
    rebrick_log_error("creating destination socket failed %d\n", result);
    rebrick_tcpsocket_destroy(cast_to_tcpsocket(client_handle));
    return;
  }
  client->id1 = socket_pair_id;
  destination->id1 = socket_pair_id;
  ferrum_raw_tcpsocket_pair_t *pair = new1(ferrum_raw_tcpsocket_pair_t);
  constructor(pair, ferrum_raw_tcpsocket_pair_t);
  pair->source = client;
  pair->destination = destination;
  pair->key = socket_pair_id;
  pair->mark = conntrack.mark;
  pair->last_used_time = rebrick_util_micro_time();
  pair->policy_last_allow_time = rebrick_util_micro_time();
  pair->client_addr = client_addr;
  socket_pair_id++;
  HASH_ADD(hh, raw->tcp_socket_pairs, key, sizeof(uint64_t), pair);
  raw->socket_count++;
}

static void on_tcp_client_error(rebrick_socket_t *socket, void *callbackdata, int32_t error) {
  unused(socket);
  unused(callbackdata);
  unused(error);
  rebrick_tcpsocket_t *tcp = cast_to_tcpsocket(socket);
  ferrum_raw_t *raw = cast(callbackdata, ferrum_raw_t *);
  ferrum_log_error("socket error occured on socket %d\n", error);
  if (tcp->is_server) {
    ferrum_log_error("server socket error occured on socket %d\n", error);
  } else {
    if (error != -14095)
      rebrick_log_error("client socket error %d\n", error);
    // if (error == (REBRICK_ERR_UV + UV_EOF) || error == (REBRICK_ERR_UV + UV_ECONNRESET)) { // client connection closed
    ferrum_raw_tcpsocket_pair_t *pair = NULL;
    HASH_FIND(hh, raw->tcp_socket_pairs, &tcp->id1, sizeof(uint64_t), pair);
    rebrick_log_info("client tcp socket closed\n");
    if (pair) {
      rebrick_log_info("delete tcp socket pair\n");
      HASH_DEL(raw->tcp_socket_pairs, pair);
      rebrick_tcpsocket_destroy(pair->destination);
      rebrick_free(pair);
    }
    rebrick_tcpsocket_destroy(tcp);
  }
}
static void on_tcp_server_close(rebrick_socket_t *socket, void *callbackdata) {
  unused(socket);
  unused(callbackdata);
  ferrum_raw_t *raw = cast(callbackdata, ferrum_raw_t *);
  ferrum_raw_tcpsocket_pair_t *el, *tmp;
  HASH_ITER(hh, raw->tcp_socket_pairs, el, tmp) {
    HASH_DEL(raw->tcp_socket_pairs, el);
    rebrick_tcpsocket_destroy(el->source);
    rebrick_tcpsocket_destroy(el->destination);
    rebrick_free(el);
  }
  raw->socket_count--;
  if (!raw->socket_count && raw->is_destroy_started)
    rebrick_free(raw);
}

void on_tcp_client_read(rebrick_socket_t *socket, void *callback_data,
                        const struct sockaddr *addr, const uint8_t *buffer, ssize_t len) {
  unused(socket);
  unused(callback_data);
  unused(addr);
  unused(buffer);
  unused(len);
  int32_t result;
  rebrick_tcpsocket_t *tcp = cast_to_tcpsocket(socket);
  ferrum_raw_t *raw = cast(callback_data, ferrum_raw_t *);
  ferrum_raw_tcpsocket_pair_t *pair = NULL;
  HASH_FIND(hh, raw->tcp_socket_pairs, &tcp->id1, sizeof(uint64_t), pair);
  if (pair) {

    pair->last_used_time = rebrick_util_micro_time();
    if (pair->policy_last_allow_time - pair->last_used_time > FERRUM_RAW_POLICY_CHECK_MS) { // every 5 seconds check
      new2(ferrum_policy_result_t, presult);
      result = ferrum_policy_execute(raw->policy, pair->mark, &presult);
      if (result) {
        rebrick_log_error("policy execute failed with error:%d\n", result);
        write_activity_log(raw->syslog, &presult, &pair->client_addr);
        rebrick_tcpsocket_destroy(pair->source);
        return;
      }
      if (presult.is_dropped) {

        rebrick_log_debug("tcp connection blocked\n");
        write_activity_log(raw->syslog, &presult, &pair->client_addr);
        rebrick_tcpsocket_destroy(pair->source);
        return;
      }
      pair->policy_last_allow_time = rebrick_util_micro_time();
    }

    uint8_t *buf = rebrick_malloc(len);
    if_is_null_then_die(buf, "malloc problem\n");
    memcpy(buf, buffer, len);
    new2(rebrick_clean_func_t, clean_func);
    clean_func.func = free_memory;
    clean_func.ptr = buf;
    int32_t result = rebrick_tcpsocket_write(pair->destination, buf, len, clean_func);
    if (result) {
      rebrick_free(buf);
    }
  }
}
void on_tcp_client_write(rebrick_socket_t *socket, void *callback_data, void *source) {
  unused(socket);
  unused(callback_data);
  unused(source);
  int32_t result;
  rebrick_tcpsocket_t *tcp = cast_to_tcpsocket(socket);
  ferrum_raw_t *raw = cast(callback_data, ferrum_raw_t *);
  ferrum_raw_tcpsocket_pair_t *pair = NULL;
  HASH_FIND(hh, raw->tcp_socket_pairs, &tcp->id1, sizeof(uint64_t), pair);
  if (pair && !pair->destination->is_reading_started) {
    size_t buflen = 0;
    result = rebrick_tcpsocket_write_buffer_size(tcp, &buflen);
    if (result) // error
      return;
    if (buflen < raw->config->socket_max_write_buf_size) { // so much data in destination buffer
      rebrick_tcpsocket_start_reading(pair->destination);
    }
  }
}

static void on_tcp_client_close(rebrick_socket_t *socket, void *callbackdata) {
  unused(socket);
  unused(callbackdata);

  ferrum_raw_t *raw = cast(callbackdata, ferrum_raw_t *);
  raw->metrics.connected_clients--;
  raw->socket_count--;

  ferrum_raw_tcpsocket_pair_t *pair = NULL;
  HASH_FIND(hh, raw->tcp_socket_pairs, &socket->id1, sizeof(uint64_t), pair);
  rebrick_log_info("client tcp socket closed\n");
  if (pair) {
    rebrick_log_info("delete tcp socket pair\n");
    HASH_DEL(raw->tcp_socket_pairs, pair);
    rebrick_free(pair);
  }

  if (!raw->socket_count && raw->is_destroy_started)
    rebrick_free(raw);
}

static void on_udp_client_write(rebrick_socket_t *socket, void *callbackdata, void *source) {
  unused(callbackdata);
  unused(socket);
  unused(source);
}
static void on_udp_destination_close(rebrick_socket_t *socket, void *callbackdata) {
  unused(socket);
  unused(callbackdata);
  ferrum_raw_udpsocket2_t *udp_callback = cast(callbackdata, ferrum_raw_udpsocket2_t *);
  ferrum_raw_t *raw = udp_callback->raw;
  ferrum_raw_udpsocket_pair_t *pair = NULL;
  HASH_FIND(hh, raw->udp_socket_pairs, &udp_callback->client_addr, sizeof(rebrick_sockaddr_t), pair);
  if (pair) {
    HASH_DEL(raw->udp_socket_pairs, pair);
    rebrick_free(pair);
  }
  rebrick_free(udp_callback);
  raw->socket_count--;
  if (!raw->socket_count && raw->is_destroy_started)
    rebrick_free(raw);
}
static void on_udp_destination_error(rebrick_socket_t *socket, void *callbackdata, int error) {
  unused(socket);
  unused(callbackdata);
  unused(error);
  ferrum_log_error("udp destination error %d\n", error);
}

static void on_udp_destination_read(rebrick_socket_t *socket, void *callbackdata, const struct sockaddr *addr,
                                    const uint8_t *buffer, ssize_t len) {
  unused(addr);
  unused(callbackdata);
  unused(socket);
  unused(addr);
  unused(buffer);
  unused(len);
  ferrum_raw_udpsocket2_t *udp_callback = cast(callbackdata, ferrum_raw_udpsocket2_t *);
  ferrum_raw_t *raw = udp_callback->raw;
  ferrum_raw_udpsocket_pair_t *pair = NULL;
  HASH_FIND(hh, raw->udp_socket_pairs, &udp_callback->client_addr, sizeof(rebrick_sockaddr_t), pair);
  if (!pair) {
    rebrick_log_fatal("pair not found at udp client");
    rebrick_udpsocket_destroy(cast_to_udpsocket(socket));
    return;
  }
  pair->last_used_time = rebrick_util_micro_time();
  // send data to backends
  uint8_t *buf = rebrick_malloc(len);
  if_is_null_then_die(buf, "malloc problem\n");
  // fill_zero(buf, len);
  memcpy(buf, buffer, len);
  new2(rebrick_clean_func_t, clean_func);
  clean_func.func = free_memory;
  clean_func.ptr = buf;

  int32_t result = rebrick_udpsocket_write(raw->listen.udp, &pair->client_addr, buf, len, clean_func);
  if (result) {
    rebrick_log_error("writing udp destination failed with error: %d\n", result);
    rebrick_free(buf);
  }
}
static void on_udp_server_error(rebrick_socket_t *socket, void *callbackdata, int error) {
  unused(socket);
  unused(callbackdata);
  unused(error);
  ferrum_log_error("udp server error %d\n", error);
}
static void on_udp_server_read(rebrick_socket_t *socket, void *callbackdata,
                               const struct sockaddr *addr,
                               const uint8_t *buffer, ssize_t len) {
  unused(addr);
  unused(callbackdata);
  unused(socket);
  unused(addr);
  unused(buffer);
  unused(len);

  // we need to create a session for 15 seconds at least
  ferrum_raw_t *raw = cast(callbackdata, ferrum_raw_t *);
  rebrick_sockaddr_t client_addr;
  fill_zero(&client_addr, sizeof(rebrick_sockaddr_t));
  int32_t result = rebrick_util_addr_to_rebrick_addr(addr, &client_addr);
  if (result) {
    ferrum_log_error("addr to rebrick addr failed %d\n", result);
    return;
  }
  char ip_str[REBRICK_IP_STR_LEN] = {0};
  char port_str[REBRICK_PORT_STR_LEN] = {0};
  result = rebrick_util_addr_to_ip_string(&client_addr, ip_str);
  if (result) {
    rebrick_log_error("sockaddr to rebrick_sockaddr failed with error:%d\n", result);
    return;
  }

  result = rebrick_util_addr_to_port_string(&client_addr, port_str);
  if (result) {
    rebrick_log_error("sockaddr to rebrick_sockaddr failed with error:%d\n", result);
    return;
  }

  ferrum_raw_udpsocket_pair_t *pair = NULL;
  HASH_FIND(hh, raw->udp_socket_pairs, &client_addr, sizeof(rebrick_sockaddr_t), pair);
  if (!pair) { // not found, query conntrack
    new2(rebrick_conntrack_t, conntrack);
    new2(ferrum_policy_result_t, presult);

    result = raw->conntrack_get(addr, &socket->bind_addr.base, FALSE, &conntrack);
    if (result) {
      rebrick_log_error("no conntrack found for ip %s:%s\n", ip_str, port_str);
      presult.is_dropped = TRUE;
      presult.why = FERRUM_POLICY_CLIENT_NOT_FOUND;
      write_activity_log(raw->syslog, &presult, &client_addr);
      return;
    }
    // execute policy, if fails close socket
    result = ferrum_policy_execute(raw->policy, conntrack.mark, &presult);
    if (result) {
      rebrick_log_error("policy execute failed with error:%d\n", result);
      write_activity_log(raw->syslog, &presult, &client_addr);
      return;
    }

    if (presult.is_dropped) {
      rebrick_log_debug("udp connection blocked %s:%s\n", ip_str, port_str);
      write_activity_log(raw->syslog, &presult, &client_addr);
      return;
    }
    // event log and continue
    write_activity_log(raw->syslog, &presult, &client_addr);

    ferrum_raw_udpsocket2_t *udp2 = new1(ferrum_raw_udpsocket2_t);
    constructor(udp2, ferrum_raw_udpsocket2_t);
    udp2->client_addr = client_addr;
    udp2->raw = raw;
    rebrick_sockaddr_t bind_addr;
    fill_zero(&bind_addr, sizeof(rebrick_sockaddr_t));
    rebrick_util_ip_port_to_addr("0.0.0.0", "0", &bind_addr);
    new2(rebrick_udpsocket_callbacks_t, callback);
    callback.callback_data = udp2;
    callback.on_close = on_udp_destination_close;
    callback.on_error = on_udp_destination_error;
    callback.on_read = on_udp_destination_read;
    callback.on_write = on_udp_client_write;
    rebrick_udpsocket_t *socket;
    result = rebrick_udpsocket_new(&socket, &bind_addr, &callback);
    if (result) {
      rebrick_log_error("client socket create failed %s:%s\n", ip_str, port_str);
      rebrick_free(udp2);
      return;
    }

    pair = new1(ferrum_raw_udpsocket_pair_t);
    constructor(pair, ferrum_raw_udpsocket_pair_t);
    pair->client_addr = client_addr;
    pair->last_used_time = rebrick_util_micro_time();
    pair->policy_last_allow_time = rebrick_util_micro_time();
    pair->udp_socket = socket;
    pair->mark = conntrack.mark;

    // session created for 30 seconds
    HASH_ADD(hh, raw->udp_socket_pairs, client_addr, sizeof(rebrick_sockaddr_t), pair);
    raw->socket_count++;
  } else {
    pair->last_used_time = rebrick_util_micro_time();

    if (pair->policy_last_allow_time - pair->last_used_time > FERRUM_RAW_POLICY_CHECK_MS) { // every 5 seconds check again
      pair->policy_last_allow_time = 0;                                                     // important
      // execute policy, if fails close socket
      new2(ferrum_policy_result_t, presult);
      result = ferrum_policy_execute(raw->policy, pair->mark, &presult);
      if (result) {
        rebrick_log_error("policy execute failed with error:%d\n", result);
        write_activity_log(raw->syslog, &presult, &pair->client_addr);
        return;
      }
      if (presult.is_dropped) {
        rebrick_log_debug("udp connection blocked %s:%s\n", ip_str, port_str);
        write_activity_log(raw->syslog, &presult, &pair->client_addr);
        return;
      }
      pair->policy_last_allow_time = rebrick_util_micro_time();
      // policy ok
      // no need to write log again
    }
  }

  // send data to backends
  uint8_t *buf = rebrick_malloc(len);
  if_is_null_then_die(buf, "malloc problem\n");
  memcpy(buf, buffer, len);
  new2(rebrick_clean_func_t, clean_func);
  clean_func.func = free_memory;
  clean_func.ptr = buf;

  result = rebrick_udpsocket_write(pair->udp_socket, &raw->listen.udp_destination_addr, buf, len, clean_func);
  if (result) {
    rebrick_log_error("writing udp destination failed with error: %d\n", result);
    rebrick_free(buf);
  }
}

static void on_udp_server_write(rebrick_socket_t *socket, void *callbackdata, void *source) {
  unused(callbackdata);
  unused(socket);
  unused(source);
}
static void on_udp_server_close(rebrick_socket_t *socket, void *callbackdata) {
  unused(socket);
  unused(callbackdata);
  ferrum_raw_t *raw = cast(callbackdata, ferrum_raw_t *);
  ferrum_raw_udpsocket_pair_t *el, *tmp;
  HASH_ITER(hh, raw->udp_socket_pairs, el, tmp) {
    HASH_DEL(raw->udp_socket_pairs, el);
    rebrick_udpsocket_destroy(el->udp_socket);
    rebrick_free(el);
  }
  raw->socket_count--;
  if (!raw->socket_count && raw->is_destroy_started)
    rebrick_free(raw);
}

int32_t udp_tracker_callback_t(void *callbackdata) {
  rebrick_log_debug("udp connection tracking called\n");
  ferrum_raw_t *raw = cast(callbackdata, ferrum_raw_t *);
  ferrum_raw_udpsocket_pair_t *el, *tmp;
  int64_t now = rebrick_util_micro_time();
  HASH_ITER(hh, raw->udp_socket_pairs, el, tmp) {
    // TODO make this fastest last used first
    if (now - el->last_used_time >= 10000) {
      rebrick_log_debug("destroying udp socket\n");
      HASH_DEL(raw->udp_socket_pairs, el);
      rebrick_udpsocket_destroy(el->udp_socket);
      rebrick_free(el);
    }
  }
  return FERRUM_SUCCESS;
}

int32_t ferrum_raw_new(ferrum_raw_t **raw, const ferrum_config_t *config,
                       const ferrum_policy_t *policy, const ferrum_syslog_t *syslog, rebrick_conntrack_get_func_t conntrack) {

  ferrum_raw_t *tmp = new1(ferrum_raw_t);
  constructor(tmp, ferrum_raw_t);
  int32_t result;
  // create tcp listening socket
  if (config->raw.listen_tcp_addr_str[0]) {
    memcpy(&tmp->listen.tcp_listening_addr, &config->raw.listen_tcp_addr, sizeof(rebrick_sockaddr_t));
    memcpy(&tmp->listen.tcp_destination_addr, &config->raw.dest_tcp_addr, sizeof(rebrick_sockaddr_t));
    new2(rebrick_tcpsocket_callbacks_t, listen_callback);
    listen_callback.callback_data = tmp;
    listen_callback.on_client_close = on_tcp_client_close;
    listen_callback.on_client_connect = on_tcp_client_connect;
    listen_callback.on_error = on_tcp_client_error;
    listen_callback.on_close = on_tcp_server_close;
    listen_callback.on_read = on_tcp_client_read;
    listen_callback.on_write = on_tcp_client_write;

    result = rebrick_tcpsocket_new2(&tmp->listen.tcp, &tmp->listen.tcp_listening_addr, NULL, 100, &listen_callback, FALSE);
    if (result) {
      ferrum_log_fatal("listening tcp socket failed at %s\n", config->raw.listen_tcp_addr_str);
      ferrum_raw_destroy(tmp);
      return result;
    }
    tmp->socket_count++;
    rebrick_log_info("tcp server started at %s\n", config->raw.listen_tcp_addr_str);
  }
  // create udp listening socket
  if (config->raw.listen_udp_addr_str[0]) {
    memcpy(&tmp->listen.udp_listening_addr, &config->raw.listen_udp_addr, sizeof(rebrick_sockaddr_t));
    memcpy(&tmp->listen.udp_destination_addr, &config->raw.dest_udp_addr, sizeof(rebrick_sockaddr_t));
    new2(rebrick_udpsocket_callbacks_t, listen_callback);
    listen_callback.callback_data = tmp;
    listen_callback.on_read = on_udp_server_read;
    listen_callback.on_write = on_udp_server_write;
    listen_callback.on_close = on_udp_server_close;
    listen_callback.on_error = on_udp_server_error;
    result = rebrick_udpsocket_new(&tmp->listen.udp, &tmp->listen.udp_listening_addr, &listen_callback);
    if (result) {
      ferrum_log_fatal("listening udp socket failed at %s\n", config->raw.listen_tcp_addr_str);
      ferrum_raw_destroy(tmp);
      return result;
    }
    tmp->socket_count++;
    rebrick_log_info("udp server started at %s\n", config->raw.listen_udp_addr_str);
  }
  tmp->config = config;
  tmp->conntrack_get = conntrack;
  tmp->policy = policy;
  tmp->syslog = syslog;
  result = rebrick_timer_new(&tmp->udp_tracker, udp_tracker_callback_t, tmp, 10 * 1000, TRUE);
  if (result) {
    ferrum_log_fatal("creating udp tracker timer failed with error:%d\n", result);
    ferrum_raw_destroy(tmp);
    return result;
  }

  *raw = tmp;

  return FERRUM_SUCCESS;
}
int32_t ferrum_raw_destroy(ferrum_raw_t *raw) {
  if (raw) {

    rebrick_timer_destroy(raw->udp_tracker);
    raw->is_destroy_started = TRUE;
    if (!raw->listen.tcp && !raw->listen.udp) {
      rebrick_free(raw);
    }
    if (raw->listen.tcp)
      rebrick_tcpsocket_destroy(raw->listen.tcp);
    if (raw->listen.udp)
      rebrick_udpsocket_destroy(raw->listen.udp);
  }
  return FERRUM_SUCCESS;
}