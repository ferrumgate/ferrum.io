#include "ferrum_raw.h"

// static uint64_t socket_pair_id = 0;

/* static void free_memory(void *data) {
  if (data)
    rebrick_free(data);
} */

static int32_t ferrum_protocol_create(ferrum_protocol_t **protocol,
                                      ferrum_raw_udpsocket_pair_t *udp,
                                      ferrum_raw_tcpsocket_pair_t *tcp,
                                      const ferrum_config_t *config,
                                      const ferrum_policy_t *policy,
                                      const ferrum_syslog_t *syslog,
                                      const ferrum_redis_t *redis_intel,
                                      const ferrum_dns_db_t *dns_db,
                                      const ferrum_track_db_t *track_db,
                                      const ferrum_authz_db_t *authz_db,
                                      const ferrum_cache_t *cache) {
  if (!strcmp(config->protocol_type, "dns"))
    return ferrum_protocol_dns_new(protocol, tcp, udp, config, policy, syslog, redis_intel, dns_db, track_db, authz_db, cache);
  else if (!strcmp(config->protocol_type, "raw"))
    return ferrum_protocol_raw_new(protocol, tcp, udp, config, policy, syslog);

  return ferrum_protocol_raw_new(protocol, tcp, udp, config, policy, syslog);
}

static void ferrum_udp_socket_pair_free(ferrum_raw_udpsocket_pair_t *udp) {
  if (udp->protocol)
    udp->protocol->destroy(udp->protocol);
  rebrick_free(udp);
}
static void ferrum_tcp_socket_pair_free(ferrum_raw_tcpsocket_pair_t *tcp) {
  if (tcp->protocol)
    tcp->protocol->destroy(tcp->protocol);
  rebrick_free(tcp);
}

static void on_tcp_destination_close(rebrick_socket_t *socket, void *callbackdata) {
  unused(socket);
  unused(callbackdata);
  ferrum_raw_t *raw = cast(callbackdata, ferrum_raw_t *);
  raw->socket_count--;
  rebrick_log_debug("socket_count %d\n", raw->socket_count);

  if (!raw->socket_count && raw->is_destroy_started)
    rebrick_free(raw);
}
static void on_tcp_destination_connect(rebrick_socket_t *socket, void *callbackdata) {
  unused(callbackdata);
  unused(socket);

  rebrick_tcpsocket_t *tcp = cast_to_tcpsocket(socket);
  ferrum_raw_t *raw = cast(callbackdata, ferrum_raw_t *);
  rebrick_log_debug("socket_count %d\n", raw->socket_count);
  ferrum_raw_tcpsocket_pair_t *pair = NULL;
  HASH_FIND(hh, raw->socket_pairs.tcp, &tcp->data1, sizeof(void *), pair);
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
  HASH_FIND(hh, raw->socket_pairs.tcp, &tcp->data1, sizeof(void *), pair);
  rebrick_log_info("destination tcp socket closed\n");
  if (pair) {
    HASH_DEL(raw->socket_pairs.tcp, pair);
    rebrick_tcpsocket_destroy(pair->source);
    ferrum_tcp_socket_pair_free(pair);
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
  int32_t result;
  rebrick_tcpsocket_t *tcp = cast_to_tcpsocket(socket);
  ferrum_raw_t *raw = cast(callback_data, ferrum_raw_t *);
  char log_id[128] = {0};
  snprintf(log_id, sizeof(log_id) - 1, "%s%" PRId64 "", raw->config->instance_id, rebrick_util_micro_time());
  ferrum_raw_tcpsocket_pair_t *pair = NULL;
  HASH_FIND(hh, raw->socket_pairs.tcp, &tcp->data1, sizeof(void *), pair);
  if (pair) {

    pair->last_used_time = rebrick_util_micro_time();
    if (pair->last_used_time - pair->policy_last_allow_time > FERRUM_RAW_POLICY_CHECK_MS) { // every 5 seconds check
      pair->policy_last_allow_time = 0;
      new2(ferrum_policy_result_t, presult);
      result = ferrum_policy_execute(raw->policy, pair->mark, &presult);
      if (result) {
        rebrick_log_error("policy execute failed with error:%d\n", result);
        ferrum_write_activity_log_raw(raw->syslog, log_id, "raw", &presult, &pair->client_addr, pair->client_ip, pair->client_port, TRUE, &raw->listen.tcp_destination_addr, raw->listen.tcp_destination_ip, raw->listen.tcp_destination_port);
        HASH_DEL(raw->socket_pairs.tcp, pair);
        rebrick_tcpsocket_destroy(pair->source);
        rebrick_tcpsocket_destroy(pair->destination);
        ferrum_tcp_socket_pair_free(pair);
        return;
      }
      if (presult.is_dropped) {

        rebrick_log_debug("tcp connection blocked\n");
        ferrum_write_activity_log_raw(raw->syslog, log_id, "raw", &presult, &pair->client_addr, pair->client_ip, pair->client_port, TRUE, &raw->listen.tcp_destination_addr, raw->listen.tcp_destination_ip, raw->listen.tcp_destination_port);
        HASH_DEL(raw->socket_pairs.tcp, pair);
        rebrick_tcpsocket_destroy(pair->source);
        rebrick_tcpsocket_destroy(pair->destination);
        ferrum_tcp_socket_pair_free(pair);
        return;
      }
      pair->policy_last_allow_time = rebrick_util_micro_time();
    }

    /*     uint8_t *buf = rebrick_malloc(len);
        if_is_null_then_die(buf, "malloc problem\n");
        memcpy(buf, buffer, len);
        new2(rebrick_clean_func_t, clean_func);
        clean_func.func = free_memory;
        clean_func.ptr = buf;
        int32_t result = rebrick_tcpsocket_write(pair->source, buf, len, clean_func);
        if (result) {
          rebrick_free(buf);
        } */
    pair->protocol->process_output_tcp(pair->protocol, buffer, len);

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
  int32_t result;
  rebrick_tcpsocket_t *tcp = cast_to_tcpsocket(socket);
  ferrum_raw_t *raw = cast(callback_data, ferrum_raw_t *);
  ferrum_raw_tcpsocket_pair_t *pair = NULL;
  HASH_FIND(hh, raw->socket_pairs.tcp, &tcp->data1, sizeof(void *), pair);
  if (pair && !pair->source->is_reading_started) {
    size_t buflen = 0;
    result = rebrick_tcpsocket_write_buffer_size(tcp, &buflen);
    if (result) // error
      return;
    if (buflen < raw->config->socket_max_write_buf_size) { // so much data in source buffer
      rebrick_tcpsocket_start_reading(pair->source);
    }
  }
}

static void on_tcp_client_connect(rebrick_socket_t *server_socket, void *callbackdata,
                                  const struct sockaddr *addr, void *client_handle) {
  unused(callbackdata);
  unused(addr);

  unused(client_handle);
  unused(socket);
  ferrum_raw_t *raw = cast(callbackdata, ferrum_raw_t *);
  char log_id[128] = {0};
  snprintf(log_id, sizeof(log_id) - 1, "%s%" PRId64 "", raw->config->instance_id, rebrick_util_micro_time());
  raw->socket_count++;
  raw->metrics.connected_clients++;
  rebrick_log_debug("socket_count %d\n", raw->socket_count);
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

  result = raw->conntrack_get(addr, &server_socket->bind_addr.base, TRUE, &conntrack);
  if (result) {
    rebrick_log_error("no conntrack found for ip %s:%s\n", ip_str, port_str);
    presult.is_dropped = TRUE;
    presult.why = FERRUM_POLICY_CLIENT_NOT_FOUND;
    ferrum_write_activity_log_raw(raw->syslog, log_id, "raw", &presult, &client_addr, ip_str, port_str, TRUE, &raw->listen.tcp_destination_addr, raw->listen.tcp_destination_ip, raw->listen.tcp_destination_port);
    rebrick_tcpsocket_destroy(cast_to_tcpsocket(client_handle));
    return;
  }
  // execute policy, if fails close socket
  result = ferrum_policy_execute(raw->policy, conntrack.mark, &presult);
  if (result) {
    rebrick_log_error("policy execute failed with error:%d\n", result);
    ferrum_write_activity_log_raw(raw->syslog, log_id, "raw", &presult, &client_addr, ip_str, port_str, TRUE, &raw->listen.tcp_destination_addr, raw->listen.tcp_destination_ip, raw->listen.tcp_destination_port);
    rebrick_tcpsocket_destroy(cast_to_tcpsocket(client_handle));
    return;
  }
  if (presult.is_dropped) {
    rebrick_log_debug("tcp connection blocked %s:%s\n", ip_str, port_str);
    ferrum_write_activity_log_raw(raw->syslog, log_id, "raw", &presult, &client_addr, ip_str, port_str, TRUE, &raw->listen.tcp_destination_addr, raw->listen.tcp_destination_ip, raw->listen.tcp_destination_port);
    rebrick_tcpsocket_destroy(cast_to_tcpsocket(client_handle));
    return;
  }

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
    ferrum_write_activity_log_raw(raw->syslog, log_id, "raw", &presult, &client_addr, ip_str, port_str, TRUE, &raw->listen.tcp_destination_addr, raw->listen.tcp_destination_ip, raw->listen.tcp_destination_port);
    rebrick_tcpsocket_destroy(cast_to_tcpsocket(client_handle));
    return;
  }
  raw->socket_count++;
  ferrum_raw_tcpsocket_pair_t *pair = new1(ferrum_raw_tcpsocket_pair_t);
  constructor(pair, ferrum_raw_tcpsocket_pair_t);
  pair->source = client;
  pair->destination = destination;
  pair->key = pair;
  pair->mark = conntrack.mark;
  pair->last_used_time = rebrick_util_micro_time();
  pair->policy_last_allow_time = rebrick_util_micro_time();
  pair->client_addr = client_addr;
  string_copy(pair->client_ip, ip_str, sizeof(pair->client_ip) - 1);
  string_copy(pair->client_port, port_str, sizeof(pair->client_port) - 1);
  memcpy(&pair->policy_result, &presult, sizeof(presult));

  result = ferrum_protocol_create(&pair->protocol, NULL, pair, raw->config, raw->policy, raw->syslog, raw->redis_intel, raw->dns_db, raw->track_db, raw->authz_db, raw->cache);
  if (result) {
    rebrick_log_error("protocol create failed %s:%s\n", ip_str, port_str);
    ferrum_write_activity_log_raw(raw->syslog, log_id, "raw", &presult, &client_addr, ip_str, port_str, TRUE, &raw->listen.udp_destination_addr, raw->listen.udp_destination_ip, raw->listen.udp_destination_port);
    rebrick_tcpsocket_destroy(cast_to_tcpsocket(client_handle));
    rebrick_tcpsocket_destroy(destination);
    ferrum_tcp_socket_pair_free(pair);
    return;
  }
  // we need in protocol codes
  pair->protocol->identity.client_id = presult.client_id;
  string_copy(pair->protocol->identity.tun_id, presult.tun_id, sizeof(pair->protocol->identity.tun_id) - 1);
  string_copy(pair->protocol->identity.user_id_first, presult.user_id, sizeof(pair->protocol->identity.user_id_first) - 1);

  // socket_pair_id++;
  HASH_ADD(hh, raw->socket_pairs.tcp, key, sizeof(void *), pair);
  client->data1 = pair;
  destination->data1 = pair;

  // event log, policy is allowed, log and continue
  if (!strcmp(pair->protocol->config->protocol_type, "raw")) // only raw protocol logs
    ferrum_write_activity_log_raw(raw->syslog, log_id, "raw", &presult, &client_addr, ip_str, port_str, TRUE, &raw->listen.tcp_destination_addr, raw->listen.tcp_destination_ip, raw->listen.tcp_destination_port);
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
    HASH_FIND(hh, raw->socket_pairs.tcp, &tcp->data1, sizeof(void *), pair);
    rebrick_log_info("client tcp socket closed\n");
    if (pair) {
      rebrick_log_info("delete tcp socket pair\n");
      HASH_DEL(raw->socket_pairs.tcp, pair);
      rebrick_tcpsocket_destroy(pair->destination);
      ferrum_tcp_socket_pair_free(pair);
    }
    rebrick_tcpsocket_destroy(tcp);
  }
}
static void on_tcp_server_close(rebrick_socket_t *socket, void *callbackdata) {
  unused(socket);
  unused(callbackdata);
  ferrum_raw_t *raw = cast(callbackdata, ferrum_raw_t *);
  ferrum_raw_tcpsocket_pair_t *el, *tmp;
  HASH_ITER(hh, raw->socket_pairs.tcp, el, tmp) {
    HASH_DEL(raw->socket_pairs.tcp, el);
    rebrick_tcpsocket_destroy(el->source);
    rebrick_tcpsocket_destroy(el->destination);
    ferrum_tcp_socket_pair_free(el);
  }
  raw->socket_count--;
  rebrick_log_debug("socket_count %d\n", raw->socket_count);
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
  char log_id[128] = {0};
  snprintf(log_id, sizeof(log_id) - 1, "%s%" PRId64 "", raw->config->instance_id, rebrick_util_micro_time());
  ferrum_raw_tcpsocket_pair_t *pair = NULL;
  HASH_FIND(hh, raw->socket_pairs.tcp, &tcp->data1, sizeof(void *), pair);
  if (pair) {

    pair->last_used_time = rebrick_util_micro_time();
    if (pair->last_used_time - pair->policy_last_allow_time > FERRUM_RAW_POLICY_CHECK_MS) { // every 5 seconds check
      pair->policy_last_allow_time = 0;
      new2(ferrum_policy_result_t, presult);
      result = ferrum_policy_execute(raw->policy, pair->mark, &presult);
      if (result) {
        rebrick_log_error("policy execute failed with error:%d\n", result);
        ferrum_write_activity_log_raw(raw->syslog, log_id, "raw", &presult, &pair->client_addr, pair->client_ip, pair->client_port, TRUE, &raw->listen.tcp_destination_addr, raw->listen.tcp_destination_ip, raw->listen.tcp_destination_port);
        HASH_DEL(raw->socket_pairs.tcp, pair);
        rebrick_tcpsocket_destroy(pair->source);
        rebrick_tcpsocket_destroy(pair->destination);
        ferrum_tcp_socket_pair_free(pair);
        return;
      }
      if (presult.is_dropped) {

        rebrick_log_debug("tcp connection blocked\n");
        ferrum_write_activity_log_raw(raw->syslog, log_id, "raw", &presult, &pair->client_addr, pair->client_ip, pair->client_port, TRUE, &raw->listen.tcp_destination_addr, raw->listen.tcp_destination_ip, raw->listen.tcp_destination_port);
        HASH_DEL(raw->socket_pairs.tcp, pair);
        rebrick_tcpsocket_destroy(pair->source);
        rebrick_tcpsocket_destroy(pair->destination);
        ferrum_tcp_socket_pair_free(pair);
        return;
      }
      pair->policy_last_allow_time = rebrick_util_micro_time();
    }

    /*  uint8_t *buf = rebrick_malloc(len);
     if_is_null_then_die(buf, "malloc problem\n");
     memcpy(buf, buffer, len);
     new2(rebrick_clean_func_t, clean_func);
     clean_func.func = free_memory;
     clean_func.ptr = buf;
     int32_t result = rebrick_tcpsocket_write(pair->destination, buf, len, clean_func);
     if (result) {
       rebrick_free(buf);
     } */
    pair->protocol->process_input_tcp(pair->protocol, buffer, len);
    if (tcp->is_reading_started) {
      size_t buflen = 0;
      result = rebrick_tcpsocket_write_buffer_size(pair->destination, &buflen);
      if (result) // error
        return;
      if (buflen > raw->config->socket_max_write_buf_size) { // so much data in destination buffer
        rebrick_tcpsocket_stop_reading(tcp);
      }
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
  HASH_FIND(hh, raw->socket_pairs.tcp, &tcp->data1, sizeof(void *), pair);
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
  rebrick_log_debug("socket_count %d\n", raw->socket_count);

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

  rebrick_free(udp_callback);
  raw->socket_count--;
  rebrick_log_debug("socket_count %d\n", raw->socket_count);
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
  int32_t result;
  ferrum_raw_udpsocket2_t *udp_callback = cast(callbackdata, ferrum_raw_udpsocket2_t *);
  ferrum_raw_t *raw = udp_callback->raw;
  char log_id[128] = {0};
  snprintf(log_id, sizeof(log_id) - 1, "%s%" PRId64 "", raw->config->instance_id, rebrick_util_micro_time());
  ferrum_raw_udpsocket_pair_t *pair = NULL;
  HASH_FIND(hh, raw->socket_pairs.udp, &udp_callback->client_addr, sizeof(rebrick_sockaddr_t), pair);
  if (!pair) {
    rebrick_log_fatal("pair not found at udp client");
    rebrick_udpsocket_destroy(cast_to_udpsocket(socket));
    return;
  }
  pair->last_used_time = rebrick_util_micro_time();
  DL_DELETE(raw->lfu.udp_list, pair);
  DL_APPEND(raw->lfu.udp_list, pair);

  // check every 5 seconds policy again
  if (pair->last_used_time - pair->policy_last_allow_time > FERRUM_RAW_POLICY_CHECK_MS) { // every 5 seconds check again
    pair->policy_last_allow_time = 0;                                                     // important
    // execute policy, if fails close socket
    new2(ferrum_policy_result_t, presult);
    result = ferrum_policy_execute(raw->policy, pair->mark, &presult);
    if (result) {
      rebrick_log_error("policy execute failed with error:%d\n", result);
      ferrum_write_activity_log_raw(raw->syslog, log_id, "raw", &presult, &pair->client_addr, pair->client_ip, pair->client_port, FALSE, &raw->listen.udp_destination_addr, raw->listen.udp_destination_ip, raw->listen.udp_destination_port);
      HASH_DEL(raw->socket_pairs.udp, pair);
      rebrick_udpsocket_destroy(pair->udp_socket);
      DL_DELETE(raw->lfu.udp_list, pair);
      ferrum_udp_socket_pair_free(pair);
      return;
    }
    if (presult.is_dropped) {
      rebrick_log_debug("udp connection blocked\n");
      ferrum_write_activity_log_raw(raw->syslog, log_id, "raw", &presult, &pair->client_addr, pair->client_ip, pair->client_port, FALSE, &raw->listen.udp_destination_addr, raw->listen.udp_destination_ip, raw->listen.udp_destination_port);
      HASH_DEL(raw->socket_pairs.udp, pair);
      rebrick_udpsocket_destroy(pair->udp_socket);
      DL_DELETE(raw->lfu.udp_list, pair);
      ferrum_udp_socket_pair_free(pair);
      return;
    }
    pair->policy_last_allow_time = rebrick_util_micro_time();
    // policy ok
    // no need to write log again
  }

  // send data to clients
  /*   uint8_t *buf = rebrick_malloc(len);
    if_is_null_then_die(buf, "malloc problem\n");
    memcpy(buf, buffer, len);
    new2(rebrick_clean_func_t, clean_func);
    clean_func.func = free_memory;
    clean_func.ptr = buf;

    struct udp_callback_data2 *data = new1(struct udp_callback_data2);
    clean_func.anydata.ptr = data;
    data->addr = pair->client_addr;
    data->len = len;

    result = rebrick_udpsocket_write(raw->listen.udp, &pair->client_addr, buf, len, clean_func);
    if (result) {
      rebrick_log_error("writing udp destination failed with error: %d\n", result);
      rebrick_free(data);
      rebrick_free(buf);
    }
    */

  pair->protocol->process_output_udp(pair->protocol, buffer, len);
  pair->source_socket_write_buf_len += len;

  if (socket->is_reading_started) {
    if (pair->source_socket_write_buf_len > raw->config->socket_max_write_buf_size) { // so much data for destination target
      rebrick_udpsocket_stop_reading(cast_to_udpsocket(socket));
    }
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
  char log_id[128] = {0};
  snprintf(log_id, sizeof(log_id) - 1, "%s%" PRId64 "", raw->config->instance_id, rebrick_util_micro_time());

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
  HASH_FIND(hh, raw->socket_pairs.udp, &client_addr, sizeof(rebrick_sockaddr_t), pair);
  if (!pair) { // not found, query conntrack
    new2(rebrick_conntrack_t, conntrack);
    new2(ferrum_policy_result_t, presult);

    result = raw->conntrack_get(addr, &socket->bind_addr.base, FALSE, &conntrack);
    if (result) {
      rebrick_log_error("no conntrack found for ip %s:%s\n", ip_str, port_str);
      presult.is_dropped = TRUE;
      presult.why = FERRUM_POLICY_CLIENT_NOT_FOUND;
      ferrum_write_activity_log_raw(raw->syslog, log_id, "raw", &presult, &client_addr, ip_str, port_str, FALSE, &raw->listen.udp_destination_addr, raw->listen.udp_destination_ip, raw->listen.udp_destination_port);
      return;
    }
    // execute policy, if fails close socket
    result = ferrum_policy_execute(raw->policy, conntrack.mark, &presult);
    if (result) {
      rebrick_log_error("policy execute failed with error:%d\n", result);
      ferrum_write_activity_log_raw(raw->syslog, log_id, "raw", &presult, &client_addr, ip_str, port_str, FALSE, &raw->listen.udp_destination_addr, raw->listen.udp_destination_ip, raw->listen.udp_destination_port);
      return;
    }

    if (presult.is_dropped) {
      rebrick_log_debug("udp connection blocked %s:%s\n", ip_str, port_str);
      ferrum_write_activity_log_raw(raw->syslog, log_id, "raw", &presult, &client_addr, ip_str, port_str, FALSE, &raw->listen.udp_destination_addr, raw->listen.udp_destination_ip, raw->listen.udp_destination_port);
      return;
    }

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
      ferrum_write_activity_log_raw(raw->syslog, log_id, "raw", &presult, &client_addr, ip_str, port_str, FALSE, &raw->listen.udp_destination_addr, raw->listen.udp_destination_ip, raw->listen.udp_destination_port);
      rebrick_free(udp2);
      return;
    }

    pair = new1(ferrum_raw_udpsocket_pair_t);
    constructor(pair, ferrum_raw_udpsocket_pair_t);
    pair->client_addr = client_addr;
    string_copy(pair->client_ip, ip_str, sizeof(pair->client_ip) - 1);
    string_copy(pair->client_port, port_str, sizeof(pair->client_port) - 1);
    memcpy(&pair->udp_destination_addr, &raw->listen.udp_destination_addr, sizeof(pair->udp_destination_addr));
    string_copy(pair->udp_destination_ip, raw->listen.udp_destination_ip, sizeof(pair->udp_destination_ip) - 1);
    string_copy(pair->udp_destination_port, raw->listen.udp_destination_port, sizeof(pair->udp_destination_port) - 1);

    pair->last_used_time = rebrick_util_micro_time();
    pair->policy_last_allow_time = rebrick_util_micro_time();
    pair->udp_socket = socket;
    pair->mark = conntrack.mark;
    pair->udp_listening_socket = raw->listen.udp;
    memcpy(&pair->policy_result, &presult, sizeof(presult));

    result = ferrum_protocol_create(&pair->protocol, pair, NULL, raw->config, raw->policy, raw->syslog, raw->redis_intel, raw->dns_db, raw->track_db, raw->authz_db, raw->cache);
    if (result) {
      rebrick_log_error("protocol create failed %s:%s\n", ip_str, port_str);
      ferrum_write_activity_log_raw(raw->syslog, log_id, "raw", &presult, &client_addr, ip_str, port_str, FALSE, &raw->listen.udp_destination_addr, raw->listen.udp_destination_ip, raw->listen.udp_destination_port);
      ferrum_udp_socket_pair_free(pair);
      return;
    }

    // session created for 30 seconds
    HASH_ADD(hh, raw->socket_pairs.udp, client_addr, sizeof(rebrick_sockaddr_t), pair);
    DL_APPEND(raw->lfu.udp_list, pair);
    raw->socket_count++;
    rebrick_log_debug("socket_count %d\n", raw->socket_count);

    // we need for loggin
    pair->protocol->identity.client_id = presult.client_id;
    string_copy(pair->protocol->identity.tun_id, presult.tun_id, sizeof(pair->protocol->identity.tun_id) - 1);
    string_copy(pair->protocol->identity.user_id_first, presult.user_id, sizeof(pair->protocol->identity.user_id_first) - 1);

    // event log and continue
    if (!strcmp(raw->config->protocol_type, "raw"))
      ferrum_write_activity_log_raw(raw->syslog, log_id, "raw", &presult, &client_addr, ip_str, port_str, FALSE, &raw->listen.udp_destination_addr, raw->listen.udp_destination_ip, raw->listen.udp_destination_port);

  } else {
    pair->last_used_time = rebrick_util_micro_time();
    DL_DELETE(raw->lfu.udp_list, pair);
    DL_APPEND(raw->lfu.udp_list, pair);

    if (pair->last_used_time - pair->policy_last_allow_time > FERRUM_RAW_POLICY_CHECK_MS) { // every 5 seconds check again
      pair->policy_last_allow_time = 0;                                                     // important
      // execute policy, if fails close socket
      new2(ferrum_policy_result_t, presult);
      result = ferrum_policy_execute(raw->policy, pair->mark, &presult);
      if (result) {
        rebrick_log_error("policy execute failed with error:%d\n", result);
        ferrum_write_activity_log_raw(raw->syslog, log_id, "raw", &presult, &client_addr, ip_str, port_str, FALSE, &raw->listen.udp_destination_addr, raw->listen.udp_destination_ip, raw->listen.udp_destination_port);
        HASH_DEL(raw->socket_pairs.udp, pair);
        rebrick_udpsocket_destroy(pair->udp_socket);
        DL_DELETE(raw->lfu.udp_list, pair);
        ferrum_udp_socket_pair_free(pair);
        return;
      }
      if (presult.is_dropped) {
        rebrick_log_debug("udp connection blocked %s:%s\n", ip_str, port_str);
        ferrum_write_activity_log_raw(raw->syslog, log_id, "raw", &presult, &client_addr, ip_str, port_str, FALSE, &raw->listen.udp_destination_addr, raw->listen.udp_destination_ip, raw->listen.udp_destination_port);
        HASH_DEL(raw->socket_pairs.udp, pair);
        rebrick_udpsocket_destroy(pair->udp_socket);
        DL_DELETE(raw->lfu.udp_list, pair);
        ferrum_udp_socket_pair_free(pair);
        return;
      }
      pair->policy_last_allow_time = rebrick_util_micro_time();
      // policy ok
      // no need to write log again
    }
  }

  // send data to backends

  /* uint8_t *buf = rebrick_malloc(len);
  if_is_null_then_die(buf, "malloc problem\n");
  memcpy(buf, buffer, len);
  new2(rebrick_clean_func_t, clean_func);
  clean_func.func = free_memory;
  clean_func.ptr = buf;

  result = rebrick_udpsocket_write(pair->udp_socket, &raw->listen.udp_destination_addr, buf, len, clean_func);
  if (result) {
    rebrick_log_error("writing udp destination failed with error: %d\n", result);
    rebrick_free(buf);
  } */
  pair->protocol->process_input_udp(pair->protocol, buffer, len);
}

static void on_udp_server_write(rebrick_socket_t *socket, void *callbackdata, void *source) {
  unused(callbackdata);
  unused(socket);
  unused(source);

  ferrum_raw_t *raw = cast(callbackdata, ferrum_raw_t *);
  ferrum_raw_udpsocket_pair_t *pair = NULL;
  if (source) {
    struct udp_callback_data2 *data = cast(source, struct udp_callback_data2 *);
    HASH_FIND(hh, raw->socket_pairs.udp, &data->addr, sizeof(rebrick_sockaddr_t), pair);
    if (pair) {
      pair->source_socket_write_buf_len -= data->len;
      if (!pair->udp_socket->is_reading_started) {
        if (pair->source_socket_write_buf_len < raw->config->socket_max_write_buf_size) {
          rebrick_udpsocket_start_reading(pair->udp_socket);
        }
      }
    }
    rebrick_free(source);
  }
}
static void on_udp_server_close(rebrick_socket_t *socket, void *callbackdata) {
  unused(socket);
  unused(callbackdata);
  rebrick_log_debug("udp server is closing\n");
  ferrum_raw_t *raw = cast(callbackdata, ferrum_raw_t *);
  ferrum_raw_udpsocket_pair_t *el, *tmp;
  HASH_ITER(hh, raw->socket_pairs.udp, el, tmp) {
    rebrick_log_debug("destination udp socket is closing\n");
    HASH_DEL(raw->socket_pairs.udp, el);
    rebrick_udpsocket_destroy(el->udp_socket);
    DL_DELETE(raw->lfu.udp_list, el);
    ferrum_udp_socket_pair_free(el);
  }
  raw->socket_count--;
  rebrick_log_debug("socket_count %d\n", raw->socket_count);
  if (!raw->socket_count && raw->is_destroy_started)
    rebrick_free(raw);
}

int32_t udp_tracker_callback_t(void *callbackdata) {
  rebrick_log_debug("udp connection tracking called\n");
  ferrum_raw_t *raw = cast(callbackdata, ferrum_raw_t *);
  ferrum_raw_udpsocket_pair_t *el, *tmp;
  int64_t now = rebrick_util_micro_time();
  DL_FOREACH_SAFE(raw->lfu.udp_list, el, tmp) {
    if (now - el->last_used_time < 10000000) // 10 seconds old, close unused sockets
      break;
    rebrick_log_debug("destroying udp socket\n");
    HASH_DEL(raw->socket_pairs.udp, el);
    DL_DELETE(raw->lfu.udp_list, el);
    rebrick_udpsocket_destroy(el->udp_socket);
    ferrum_udp_socket_pair_free(el);
  }
  return FERRUM_SUCCESS;
}

int32_t ferrum_raw_new(ferrum_raw_t **raw, const ferrum_config_t *config,
                       const ferrum_policy_t *policy,
                       const ferrum_syslog_t *syslog,
                       const ferrum_redis_t *redis_intel,
                       const ferrum_dns_db_t *dns_db,
                       const ferrum_track_db_t *track_db,
                       const ferrum_authz_db_t *authz_db,
                       const ferrum_cache_t *cache,
                       rebrick_conntrack_get_func_t conntrack) {

  ferrum_raw_t *tmp = new1(ferrum_raw_t);
  constructor(tmp, ferrum_raw_t);
  int32_t result;
  // create tcp listening socket
  if (config->raw.listen_tcp_addr_str[0]) {
    memcpy(&tmp->listen.tcp_listening_addr, &config->raw.listen_tcp_addr, sizeof(rebrick_sockaddr_t));
    memcpy(&tmp->listen.tcp_destination_addr, &config->raw.dest_tcp_addr, sizeof(rebrick_sockaddr_t));

    rebrick_util_addr_to_ip_string(&tmp->listen.tcp_destination_addr, tmp->listen.tcp_destination_ip);     // dont need to check result
    rebrick_util_addr_to_port_string(&tmp->listen.tcp_destination_addr, tmp->listen.tcp_destination_port); // dont need to check resutl

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
    rebrick_log_debug("socket_count %d\n", tmp->socket_count);
    rebrick_log_info("tcp server started at %s\n", config->raw.listen_tcp_addr_str);
  }
  // create udp listening socket
  if (config->raw.listen_udp_addr_str[0]) {
    memcpy(&tmp->listen.udp_listening_addr, &config->raw.listen_udp_addr, sizeof(rebrick_sockaddr_t));
    memcpy(&tmp->listen.udp_destination_addr, &config->raw.dest_udp_addr, sizeof(rebrick_sockaddr_t));

    rebrick_util_addr_to_ip_string(&tmp->listen.udp_destination_addr, tmp->listen.udp_destination_ip);     // dont need to check result
    rebrick_util_addr_to_port_string(&tmp->listen.udp_destination_addr, tmp->listen.udp_destination_port); // dont need to check resutl

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
    rebrick_log_debug("socket_count %d\n", tmp->socket_count);
    rebrick_log_info("udp server started at %s\n", config->raw.listen_udp_addr_str);
  }
  tmp->config = config;
  tmp->conntrack_get = conntrack;
  tmp->policy = policy;
  tmp->syslog = syslog;
  tmp->dns_db = dns_db;
  tmp->authz_db = authz_db;
  tmp->track_db = track_db;
  tmp->redis_intel = redis_intel;
  tmp->cache = cache;
  result = rebrick_timer_new(&tmp->udp_tracker, udp_tracker_callback_t, tmp, 3000, TRUE);
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

    if (raw->listen.tcp)
      rebrick_tcpsocket_destroy(raw->listen.tcp);
    if (raw->listen.udp)
      rebrick_udpsocket_destroy(raw->listen.udp);
    if (!raw->listen.tcp && !raw->listen.udp) {
      rebrick_free(raw);
    }
  }
  return FERRUM_SUCCESS;
}