#include "ferrum_protocol_dns.h"

typedef struct {
  ferrum_dns_cache_t *cache;
  rebrick_timer_t *cache_cleaner;
} ferrum_dns_data_t;

#define cast_to_dns_data(x) ((ferrum_dns_data_t *)(x))
#define cast_to_dns_data_var(x, y) ferrum_dns_data_t *y = (ferrum_dns_data_t *)(x)

static void free_memory(void *data) {
  if (data)
    rebrick_free(data);
}

int32_t ferrum_dns_packet_destroy(ferrum_dns_packet_t *dns) {
  if (dns) {
    if (dns->query)
      rebrick_free(dns->query);
    rebrick_free(dns);
  }
  return FERRUM_SUCCESS;
}

uint32_t ferrum_dns_packet_crc(ferrum_dns_packet_t *dns) {
  unsigned int crc = 0xffffffff;
  // crc calculation
  uint8_t *p1;
  uint8_t *tmp;
  for (p1 = (unsigned char *)dns->query; *p1; p1++) {
    int i = 8;
    char c = *p1;

    if (c >= 'A' && c <= 'Z')
      c += 'a' - 'A';

    crc ^= c << 24;
    while (i--)
      crc = crc & 0x80000000 ? (crc << 1) ^ 0x04c11db7 : crc << 1;
  }
  // class
  p1 = cast_to_uint8ptr(&dns->query_class);
  tmp = p1 + sizeof(dns->query_class);
  for (; p1 < tmp; p1++) {
    int i = 8;
    crc ^= *p1 << 24;
    while (i--)
      crc = crc & 0x80000000 ? (crc << 1) ^ 0x04c11db7 : crc << 1;
  }
  // query type
  p1 = cast_to_uint8ptr(&dns->query_type);
  tmp = p1 + sizeof(dns->query_type);
  for (; p1 < tmp; p1++) {
    int i = 8;
    crc ^= *p1 << 24;
    while (i--)
      crc = crc & 0x80000000 ? (crc << 1) ^ 0x04c11db7 : crc << 1;
  }
  return crc;
}

int32_t ferrum_dns_packet_from(const uint8_t *buffer, size_t len, ferrum_dns_packet_t *dns) {
  /* dns */
  ldns_status status;
  ldns_pkt *query_pkt;
  ldns_rr *query_rr;
  status = ldns_wire2pkt(&query_pkt, buffer, (size_t)len);
  if (status != LDNS_STATUS_OK) {
    ferrum_log_debug("dns bad packet: %s\n", ldns_get_errorstr_by_id(status));
    return FERRUM_ERR_DNS_BAD_PACKET;
  }
  ldns_pkt_opcode opcode = ldns_pkt_get_opcode(query_pkt);
  if (opcode != LDNS_PACKET_QUERY) {
    ferrum_log_warn("dns is not query\n");
    return FERRUM_ERR_DNS_NOT_QUERY; // silent drop packet
  }

  query_rr = ldns_rr_list_rr(ldns_pkt_question(query_pkt), 0);

  dns->query_class = ldns_rr_get_class(query_rr);
  dns->query_type = ldns_rr_get_type(query_rr);
  dns->query_id = ldns_pkt_id(query_pkt);
  dns->flags.rd = ldns_pkt_rd(query_pkt);
  dns->flags.ra = ldns_pkt_ra(query_pkt);
  dns->query_newid = rebrick_util_rand16();

  ldns_buffer *lbuf = ldns_buffer_new(LDNS_MAX_PACKETLEN);
  ldns_buffer_clear(lbuf);
  status = ldns_rdf2buffer_str_dname(lbuf, ldns_rr_owner(query_rr));
  if (status != LDNS_STATUS_OK) {
    ferrum_log_debug("dns bad packet: %s\n", ldns_get_errorstr_by_id(status));
    ldns_buffer_free(lbuf);
    ldns_pkt_free(query_pkt);
    return FERRUM_ERR_DNS_BAD_PACKET;
  }
  char *fqdn = ldns_buffer2str(lbuf);
  if (!fqdn) {
    ferrum_log_debug("dns bad packet \n");
    ldns_buffer_free(lbuf);
    ldns_pkt_free(query_pkt);
    return FERRUM_ERR_DNS_BAD_PACKET;
  }

  size_t fqdn_len = strlen(fqdn);
  dns->query = rebrick_malloc(fqdn_len + 1);
  if_is_null_then_die(dns->query, "malloc problem\n");
  memset(dns->query, 0, fqdn_len + 1);
  if (fqdn_len)
    strncpy(dns->query, fqdn, fqdn_len);

  /* if (dns->query[0] != '.') {
    size_t slen = strlen(dns->query);
    dns->query[slen - 1] = 0;
  } */
  dns->query_crc = ferrum_dns_packet_crc(dns);

  dns->edns.present = ldns_pkt_edns(query_pkt) && ldns_pkt_edns_data(query_pkt);
  if (dns->edns.present) {
    // dns->edns.data = ldns_rdf_clone(ldns_pkt_edns_data(query_pkt));
    dns->edns.udp_size = ldns_pkt_edns_udp_size(query_pkt);
    dns->edns.extended_rcode = ldns_pkt_edns_extended_rcode(query_pkt);
    dns->edns.version = ldns_pkt_edns_extended_rcode(query_pkt);
    dns->edns.z = ldns_pkt_edns_z(query_pkt);
    // dns->edns.list = ldns_edns_option_list_clone(ldns_pkt_edns_get_option_list(query_pkt));
  }
  rebrick_free(fqdn);
  ldns_buffer_free(lbuf);
  ldns_pkt_free(query_pkt);

  ferrum_log_debug("dns packet query:%s type:%d class:%d id:%d crc:%d\n", dns->query, dns->query_type, dns->query_class, dns->query_id, dns->query_crc);

  return FERRUM_SUCCESS;
}

int32_t ferrum_dns_reply_empty_packet(ferrum_dns_packet_t *dns, ldns_pkt_rcode rcode, uint8_t **answer, size_t *answer_size) {

  ldns_pkt *answer_pkt;
  ldns_status status = ldns_pkt_query_new_frm_str(&answer_pkt, dns->query, dns->query_type, dns->query_class, 0);
  if (status != LDNS_STATUS_OK) {
    ferrum_log_warn("dns packet query create failed %s error:%d\n", dns->query, status);
    return FERRUM_ERR_DNS;
  }

  ldns_pkt_set_qr(answer_pkt, 1);
  ldns_pkt_set_aa(answer_pkt, 0);
  ldns_pkt_set_opcode(answer_pkt, 0);
  ldns_pkt_set_rcode(answer_pkt, rcode);
  ldns_pkt_set_id(answer_pkt, dns->query_id);
  ldns_pkt_set_ancount(answer_pkt, 0);
  ldns_pkt_set_rd(answer_pkt, dns->flags.rd);
  ldns_pkt_set_ra(answer_pkt, 1);
  if (dns->edns.present) {
    ldns_pkt_set_edns_udp_size(answer_pkt, 1280);
  }

  status = ldns_pkt2wire(answer, answer_pkt, answer_size);
  if (status != LDNS_STATUS_OK) {
    ldns_pkt_free(answer_pkt);
    return FERRUM_ERR_DNS;
  }
  ldns_pkt_free(answer_pkt);
  return FERRUM_SUCCESS;
}

int32_t ferrum_dns_reply_ip_packet(ferrum_dns_packet_t *dns, const char *ip, uint16_t ttl, uint8_t **answer, size_t *answer_size) {

  if (!ip)
    return FERRUM_ERR_DNS_BAD_ARGUMENT;
  if (!ip[0])
    return FERRUM_ERR_DNS_BAD_ARGUMENT; // empty ip
  if (!dns->query[0])
    return FERRUM_ERR_DNS_BAD_ARGUMENT; // empty query

  ldns_pkt *answer_pkt;

  ldns_status status = ldns_pkt_query_new_frm_str(&answer_pkt, dns->query, dns->query_type, dns->query_class, 0);
  if (status != LDNS_STATUS_OK) {
    ferrum_log_warn("dns packet query create failed %s error:%d\n", dns->query, status);
    return FERRUM_ERR_DNS;
  }

  ldns_pkt_set_qr(answer_pkt, 1);
  ldns_pkt_set_aa(answer_pkt, 0);
  ldns_pkt_set_opcode(answer_pkt, 0);
  ldns_pkt_set_rcode(answer_pkt, LDNS_RCODE_NOERROR);
  ldns_pkt_set_id(answer_pkt, dns->query_id);
  ldns_pkt_set_ancount(answer_pkt, 0);
  ldns_pkt_set_rd(answer_pkt, dns->flags.rd);
  ldns_pkt_set_ra(answer_pkt, 1);

  ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(answer_pkt), 0);
  ldns_rdf *owner = ldns_rr_owner(question);

  bool is_ipv4 = strchr(ip, '.') ? true : false;

  ldns_rr *answer_rr = ldns_rr_new_frm_type(is_ipv4 ? LDNS_RR_TYPE_A : LDNS_RR_TYPE_AAAA);
  ldns_rdf *cloned = ldns_rdf_clone(owner);
  ldns_rr_set_owner(answer_rr, cloned);
  ldns_rr_set_ttl(answer_rr, ttl);
  ldns_rr_set_class(answer_rr, dns->query_class);
  ldns_rdf *ip_val;

  if (is_ipv4)
    status = ldns_str2rdf_a(&ip_val, ip);
  else
    status = ldns_str2rdf_aaaa(&ip_val, ip);

  if (status != LDNS_STATUS_OK) {
    ldns_pkt_free(answer_pkt);
    return FERRUM_ERR_DNS;
  }
  ldns_rr_a_set_address(answer_rr, ip_val);

  ldns_pkt_push_rr(answer_pkt, LDNS_SECTION_ANSWER, answer_rr);

  if (dns->edns.present) {
    ldns_pkt_set_edns_udp_size(answer_pkt, 1280);
  }

  status = ldns_pkt2wire(answer, answer_pkt, answer_size);
  if (status != LDNS_STATUS_OK) {
    ldns_pkt_free(answer_pkt);

    return FERRUM_ERR_DNS;
  }

  ldns_pkt_free(answer_pkt);

  return FERRUM_SUCCESS;
}

int32_t reply_dns_empty(ferrum_raw_udpsocket_pair_t *pair, ferrum_dns_packet_t *dns, ldns_pkt_rcode rcode) {
  uint8_t *buf;
  size_t buf_len;
  int32_t result = ferrum_dns_reply_empty_packet(dns, rcode, &buf, &buf_len);
  if (result) { // there is error, drop it
    return result;
  }
  new2(rebrick_clean_func_t, clean_func);
  clean_func.func = free_memory;
  clean_func.ptr = buf;

  result = rebrick_udpsocket_write(pair->udp_listening_socket, &pair->client_addr, buf, buf_len, clean_func);
  if (result) {
    rebrick_log_error("writing udp destination failed with error: %d\n", result);
    rebrick_free(buf);
    return result;
  }
  return FERRUM_SUCCESS;
}

int32_t reply_dns_ip(ferrum_raw_udpsocket_pair_t *pair, ferrum_dns_packet_t *dns, char ip[REBRICK_IP_STR_LEN], uint16_t ttl) {
  uint8_t *buf;
  size_t buf_len;
  int32_t result = ferrum_dns_reply_ip_packet(dns, ip, ttl, &buf, &buf_len);
  if (result) { // there is error, drop it
    return result;
  }
  new2(rebrick_clean_func_t, clean_func);
  clean_func.func = free_memory;
  clean_func.ptr = buf;

  result = rebrick_udpsocket_write(pair->udp_listening_socket, &pair->client_addr, buf, buf_len, clean_func);
  if (result) {
    rebrick_log_error("writing udp destination failed with error: %d\n", result);
    rebrick_free(buf);
    return result;
  }
  return FERRUM_SUCCESS;
}

static int32_t process_input_udp(ferrum_protocol_t *protocol, const uint8_t *buffer, size_t len) {
  unused(protocol);
  unused(buffer);
  unused(len);

  ferrum_raw_udpsocket_pair_t *pair = protocol->pair.udp;
  new2(ferrum_dns_packet_t, dns);
  int32_t result = ferrum_dns_packet_from(buffer, len, &dns);
  if (result) { // parse problem, only log, send to backends
    // return reply_dns(pair, &dns, LDNS_RCODE_SERVFAIL);
    rebrick_log_warn("dns packet parse error %d\n", result);
  }

  // check if query ends with our root domain
  // no log
  if (!result && rebrick_util_fqdn_endswith(dns.query, protocol->config->root_fqdn)) {
    if (dns.query_type == LDNS_RR_TYPE_AAAA) { // return nx
      result = reply_dns_empty(pair, &dns, LDNS_RCODE_NXDOMAIN);
      if (!result)
        return result; // if success return otherwise send to backends
    }
    if (dns.query_type == LDNS_RR_TYPE_A) { // check root fqdn ip address
      char ip[REBRICK_IP_STR_LEN] = {0};
      result = ferrum_dns_db_find_local_a(protocol->dns_db, dns.query, ip);
      if (result) { // error, return error
        result = reply_dns_empty(pair, &dns, LDNS_RCODE_SERVFAIL);
        if (!result) // if success then return
          return result;
      } else if (!ip[0]) { // nx result
        result = reply_dns_empty(pair, &dns, LDNS_RCODE_NXDOMAIN);
        if (!result) // if success then return
          return result;
      } else
        result = reply_dns_ip(pair, &dns, ip, 300);
      if (!result) // if success then return
        return result;
    }
  }

  // check if domain is in ignore list

  // TODO log dns request
  // send backend, put to cache
  // check if request is in ignore, white or blacklist

  uint8_t *buf = rebrick_malloc(len);
  if_is_null_then_die(buf, "malloc problem\n");
  memcpy(buf, buffer, len);
  new2(rebrick_clean_func_t, clean_func);
  clean_func.func = free_memory;
  clean_func.ptr = buf;

  result = rebrick_udpsocket_write(pair->udp_socket, &pair->udp_destination_addr, buf, len, clean_func);
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

  // TODO log dns reply

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
  // TODO udp like process
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
  // TODO udp like process
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
static int32_t dns_cache_clean(void *callback) {
  unused(callback);
  ferrum_protocol_t *dns = cast(callback, ferrum_protocol_t *);
  cast_to_dns_data_var(dns->data, dns_data);
  ferrum_log_debug("cleaning dns cache\n");
  ferrum_dns_cache_clear_timedoutdata(dns_data->cache);
  return FERRUM_SUCCESS;
}

int32_t ferrum_protocol_dns_destroy(ferrum_protocol_t *protocol) {
  unused(protocol);
  if (protocol) {
    cast_to_dns_data_var(protocol->data, dns_data);
    if (dns_data) {
      if (dns_data->cache)
        ferrum_dns_cache_destroy(dns_data->cache);
      if (dns_data->cache_cleaner)
        rebrick_timer_destroy(dns_data->cache_cleaner);
    }
    rebrick_free(protocol);
  }
  return FERRUM_SUCCESS;
}

int32_t ferrum_protocol_dns_new(ferrum_protocol_t **protocol,
                                ferrum_raw_tcpsocket_pair_t *tcp_pair,
                                ferrum_raw_udpsocket_pair_t *udp_pair,
                                const ferrum_config_t *config,
                                const ferrum_policy_t *policy,
                                const ferrum_syslog_t *syslog,
                                const ferrum_redis_t *redis_intel,
                                const ferrum_dns_db_t *dns_db,
                                const ferrum_track_db_t *track_db,
                                const ferrum_authz_db_t *authz_db) {
  ferrum_protocol_t *tmp = new1(ferrum_protocol_t);
  constructor(tmp, ferrum_protocol_t);
  tmp->config = config;
  tmp->syslog = syslog;
  tmp->policy = policy;
  tmp->redis_intel = redis_intel;
  tmp->dns_db = dns_db;
  tmp->track_db = track_db;
  tmp->authz_db = authz_db;
  tmp->pair.tcp = tcp_pair;
  tmp->pair.udp = udp_pair;

  tmp->process_input_tcp = process_input_tcp;
  tmp->process_output_tcp = process_output_tcp;
  tmp->process_input_udp = process_input_udp;
  tmp->process_output_udp = process_output_udp;
  tmp->destroy = ferrum_protocol_dns_destroy;

  tmp->data = new1(ferrum_dns_data_t);
  if_is_null_then_die(tmp->data, "malloc problem\n");

  ferrum_dns_cache_t *cache;
  int32_t result = ferrum_dns_cache_new(&cache, 10000);
  if (result) {
    ferrum_log_error("dns cache create failed with error:%d\n", result);
    ferrum_protocol_dns_destroy(tmp);
    return result;
  }
  cast_to_dns_data(tmp->data)->cache = cache;

  rebrick_timer_t *cache_cleaner;
  result = rebrick_timer_new(&cache_cleaner, dns_cache_clean, tmp, 10000, TRUE);
  if (result) {
    ferrum_log_error("dns cache timer create failed with error:%d\n", result);
    ferrum_protocol_dns_destroy(tmp);
    return result;
  }
  cast_to_dns_data(tmp->data)->cache_cleaner = cache_cleaner;

  *protocol = tmp;
  return FERRUM_SUCCESS;
}
