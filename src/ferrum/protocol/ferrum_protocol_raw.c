#include "ferrum_protocol_raw.h"

static void free_memory(void *data) {
  if (data)
    rebrick_free(data);
}

static int32_t process_input_udp(ferrum_protocol_t *protocol, const uint8_t *buffer, size_t len) {
  unused(protocol);
  unused(buffer);
  unused(len);

  ferrum_raw_udpsocket_pair_t *pair = protocol->pair.udp;
  /*  if (!protocol->data) { // only when connected
     char log_id[128] = {0};
     snprintf(log_id, sizeof(log_id) - 1, "%s%" PRId64 "", protocol->config->instance_id, rebrick_util_micro_time());
     ferrum_write_activity_log_raw(protocol->syslog, log_id, "Raw", &pair->policy_result, &pair->client_addr,
                                   pair->client_ip, pair->client_port, FALSE, &pair->udp_destination_addr, pair->udp_destination_ip, pair->udp_destination_port);
     protocol->data = (void *)1; // any invalid pointer data, dont delete it or deference it
   } */

  uint8_t *buf = rebrick_malloc(len);
  if_is_null_then_die(buf, "malloc problem\n");
  memcpy(buf, buffer, len);
  new2(rebrick_clean_func_t, clean_func);
  clean_func.func = free_memory;
  clean_func.ptr = buf;

  int32_t result = rebrick_udpsocket_write(pair->udp_socket, &pair->udp_destination_addr, buf, len, clean_func);
  if (result) {
    rebrick_log_error("writing udp destination failed with error: %d\n", result);
    rebrick_free(buf);
    return result;
  }

  return FERRUM_SUCCESS;
}
static int32_t process_output_udp(ferrum_protocol_t *protocol, const uint8_t *buffer, size_t len) {
  unused(protocol);
  unused(buffer);
  unused(len);

  ferrum_raw_udpsocket_pair_t *pair = protocol->pair.udp;
  uint8_t *buf = rebrick_malloc(len);
  if_is_null_then_die(buf, "malloc problem\n");
  memcpy(buf, buffer, len);
  new2(rebrick_clean_func_t, clean_func);
  clean_func.func = free_memory;
  clean_func.ptr = buf;

  struct udp_callback_data2 *data = new1(struct udp_callback_data2);
  clean_func.anydata.ptr = data;
  data->addr = pair->client_addr;
  data->len = len;

  int32_t result = rebrick_udpsocket_write(pair->udp_listening_socket, &pair->client_addr, buf, len, clean_func);
  if (result) {
    rebrick_log_error("writing udp destination failed with error: %d\n", result);
    rebrick_free(data);
    rebrick_free(buf);
    return result;
  }

  return FERRUM_SUCCESS;
}

static int32_t process_input_tcp(ferrum_protocol_t *protocol, const uint8_t *buffer, size_t len) {
  unused(protocol);
  unused(buffer);
  unused(len);
  ferrum_raw_tcpsocket_pair_t *pair = protocol->pair.tcp;
  uint8_t *buf = rebrick_malloc(len);
  if_is_null_then_die(buf, "malloc problem\n");
  memcpy(buf, buffer, len);
  new2(rebrick_clean_func_t, clean_func);
  clean_func.func = free_memory;
  clean_func.ptr = buf;
  int32_t result = rebrick_tcpsocket_write(pair->destination, buf, len, clean_func);
  if (result) {
    rebrick_free(buf);
    return result;
  }

  return FERRUM_SUCCESS;
}
static int32_t process_output_tcp(ferrum_protocol_t *protocol, const uint8_t *buffer, size_t len) {
  unused(protocol);
  unused(buffer);
  unused(len);
  ferrum_raw_tcpsocket_pair_t *pair = protocol->pair.tcp;
  uint8_t *buf = rebrick_malloc(len);
  if_is_null_then_die(buf, "malloc problem\n");
  memcpy(buf, buffer, len);
  new2(rebrick_clean_func_t, clean_func);
  clean_func.func = free_memory;
  clean_func.ptr = buf;
  int32_t result = rebrick_tcpsocket_write(pair->source, buf, len, clean_func);
  if (result) {
    rebrick_free(buf);
    return result;
  }

  return FERRUM_SUCCESS;
}

int32_t ferrum_protocol_raw_destroy(ferrum_protocol_t *protocol) {
  unused(protocol);
  rebrick_free(protocol);
  return FERRUM_SUCCESS;
}

int32_t
ferrum_protocol_raw_new(ferrum_protocol_t **protocol,
                        ferrum_raw_tcpsocket_pair_t *tcp_pair,
                        ferrum_raw_udpsocket_pair_t *udp_pair,
                        const ferrum_config_t *config,
                        const ferrum_policy_t *policy,
                        const ferrum_syslog_t *syslog) {
  ferrum_protocol_t *tmp = new1(ferrum_protocol_t);
  constructor(tmp, ferrum_protocol_t);
  tmp->config = config;
  tmp->syslog = syslog;
  tmp->policy = policy;
  tmp->pair.tcp = tcp_pair;
  tmp->pair.udp = udp_pair;

  tmp->process_input_tcp = process_input_tcp;
  tmp->process_output_tcp = process_output_tcp;
  tmp->process_input_udp = process_input_udp;
  tmp->process_output_udp = process_output_udp;
  tmp->destroy = ferrum_protocol_raw_destroy;

  *protocol = tmp;
  return FERRUM_SUCCESS;
}
