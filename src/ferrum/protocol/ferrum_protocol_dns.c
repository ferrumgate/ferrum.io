#include "ferrum_protocol_dns.h"

#define FERRUM_FQDN_CATEGORY_WHITE_LIST "hx396d3DptCY1rCq"
#define FERRUM_FQDN_CATEGORY_BLACK_LIST "cAhXVPaFm1NVSJxF"
#define FERRUM_FQDN_CATEGORY_UNKNOWN "w9FTQWw5e56Txcld"

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
    dns->ref_count--;
    if (dns->ref_count) // after last member, destroy it
      return FERRUM_SUCCESS;
    if (dns->query)
      rebrick_free(dns->query);
    if (dns->state.authz_id)
      rebrick_free(dns->state.authz_id);
    if (dns->state.redis_query_list)
      rebrick_free(dns->state.redis_query_list);
    if (dns->state.redis_response)
      rebrick_free(dns->state.redis_response);
    if (dns->state.reply_buf)
      rebrick_free(dns->state.reply_buf);
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
  dns->query_newid = dns->query_id; // for future uses rebrick_util_rand16();

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

  if (dns->query[0] != '.') {
    // size_t slen = strlen(dns->query);
    dns->query[fqdn_len - 1] = 0;
  }
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

int32_t reply_dns_ip(ferrum_raw_udpsocket_pair_t *pair, ferrum_dns_packet_t *dns, char *ip, uint16_t ttl) {
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

int32_t db_get_user_and_group_ids(ferrum_protocol_t *protocol, uint32_t mark) {
  int64_t now = rebrick_util_micro_time();
  if (now - protocol->identity.last_check < 5 * 1000 * 1000)
    return FERRUM_SUCCESS;

  ferrum_track_db_row_t *track;
  int32_t result = ferrum_track_db_get_data(protocol->track_db, mark, &track);
  if (result) {
    ferrum_log_error("track db get data failed with error:%d\n", result);
    return result; // if fails return
  }
  rebrick_free_if_not_null_and_set_null(protocol->identity.user_id);
  rebrick_free_if_not_null_and_set_null(protocol->identity.group_ids);
  if (!track) // not found, user not found
  {
    ferrum_log_debug("trackId %d not found\n", mark);
    return FERRUM_SUCCESS;
  }

  if (track->user_id)
    protocol->identity.user_id = strdup(track->user_id);
  if (track->group_ids)
    protocol->identity.group_ids = strdup(track->group_ids);
  ferrum_track_db_row_destroy(track);
  protocol->identity.last_check = now;
  return FERRUM_SUCCESS;
}

int32_t send_backend_directly(ferrum_protocol_t *protocol, ferrum_raw_udpsocket_pair_t *pair, ferrum_dns_packet_t *dns, const uint8_t *buffer, size_t len) {
  unused(dns);
  unused(protocol);
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

int merge_fqdn_for_redis(const char *fqdn, char **dest) {
  *dest = NULL;
  size_t len = 1024;
  char *str;
  rebrick_malloc2(str, len);
  size_t str_pos = 0;
  str_pos = snprintf(str, len - 1, "MGET ");
  while (*fqdn && *fqdn == '.') {
    fqdn++;
  }
  while (*fqdn) {
    size_t tmp_len = strlen(fqdn);
    if (str_pos + tmp_len + 1 >= len) {
      str = rebrick_realloc(str, len + 1024);
      len += 1024;
    }
    str_pos += snprintf(str + str_pos, len - 1, "/fqdn/%s/list ", fqdn);

    while (*fqdn && *fqdn != '.') {
      fqdn++;
    }
    while (*fqdn && *fqdn == '.') {
      fqdn++;
    }
  }
  *dest = str;
  return REBRICK_SUCCESS;
}

int split_fqdn_for_redis(const char *fqdn, ferrum_redis_dns_query_t **dest, size_t *dest_len) {
  *dest = NULL;
  *dest_len = 0;
  while (*fqdn && *fqdn == '.') {
    fqdn++;
  }

  ferrum_redis_dns_query_t *rquery = NULL;
  rebrick_malloc2(rquery, sizeof(ferrum_redis_dns_query_t) * 8);
  size_t counter = 0;
  size_t total = 8;
  while (*fqdn) {

    if (counter == total) {
      rquery = rebrick_realloc(rquery, sizeof(ferrum_redis_dns_query_t) * (total + 8));
      total += 8;
    }
    rquery[counter].query = fqdn;
    counter++;
    while (*fqdn && *fqdn != '.') {
      fqdn++;
    }
    while (*fqdn && *fqdn == '.') {
      fqdn++;
    }
  }
  if (counter) {
    *dest = rquery;
    *dest_len = counter;
  } else {
    rebrick_free(rquery);
  }
  return REBRICK_SUCCESS;
}

static int32_t redis_counter = 0;

static int32_t send_client_directly(ferrum_protocol_t *protocol, const uint8_t *buffer, size_t len);
int32_t db_get_authz_fqdn_intelligence(char *content, const char *name, char **fqdns, char **lists);

static inline void write_activity_log(ferrum_protocol_t *protocol, ferrum_raw_udpsocket_pair_t *pair, ferrum_dns_packet_t *dns,
                                      enum ferrum_dns_status status, const char *category, const char *list_id) {
  char log_id[128] = {0};
  size_t len = snprintf(log_id, sizeof(log_id) - 1, "%s%" PRId64 "", protocol->config->instance_id, rebrick_util_micro_time());
  unused(len);
  ferrum_write_activity_log_dns(protocol->syslog, log_id, protocol->config->protocol_type,
                                &pair->client_addr, pair->client_ip, pair->client_port, 0,
                                &pair->udp_destination_addr, pair->udp_destination_ip, pair->udp_destination_port,
                                pair->mark, dns->state.authz_id, protocol->identity.user_id, protocol->identity.tun_id,
                                dns->query_type == LDNS_RR_TYPE_A ? FERRUM_ACTIVITY_DNS_A : FERRUM_ACTIVITY_DNS_AAAA,
                                dns->query, status, category, list_id);

  // ferrum_write_activity_log(protocol->syslog, log_id, len);
}

int32_t process_dns_state(ferrum_protocol_t *protocol, ferrum_raw_udpsocket_pair_t *pair, ferrum_dns_packet_t *dns) {
  unused(protocol);
  unused(pair);
  unused(dns);
  int32_t result;

  if (!dns->state.is_client_replied &&
      dns->state.is_backend_received &&
      (dns->state.is_redis_query_received ||
       dns->state.is_redis_query_error ||
       dns->state.is_redis_query_not_found)) {
    dns->state.is_client_replied = TRUE; // sended back to client
    if (dns->state.is_redis_query_error) {
      rebrick_log_debug("dns state is redis error %s\n", dns->query);
      write_activity_log(protocol, pair, dns, FERRUM_DNS_STATUS_ERROR, FERRUM_FQDN_CATEGORY_UNKNOWN, NULL);
      result = send_client_directly(protocol, dns->state.reply_buf, dns->state.reply_buf_len);
      return result;
    } else if (dns->state.is_redis_query_not_found) {
      rebrick_log_debug("dns state is query not found %s\n", dns->query);
      write_activity_log(protocol, pair, dns, FERRUM_DNS_STATUS_ALLOW, FERRUM_FQDN_CATEGORY_UNKNOWN, NULL);
      result = send_client_directly(protocol, dns->state.reply_buf, dns->state.reply_buf_len);
      return result;
    } else if (dns->state.is_redis_query_received) {
      rebrick_log_debug("dns state is query received %s\n", dns->query);

      // get auth rule
      ferrum_authz_db_authz_row_t *authz = NULL;
      result = ferrum_authz_db_get_authz_data(protocol->authz_db, dns->state.authz_id, &authz);
      if (result) {
        ferrum_log_error("authz db get authz failed with error:%d\n", result);
        write_activity_log(protocol, pair, dns, FERRUM_DNS_STATUS_ERROR, FERRUM_FQDN_CATEGORY_UNKNOWN, NULL);
        result = send_client_directly(protocol, dns->state.reply_buf, dns->state.reply_buf_len);
        return result;
      }
      if (!authz) // rule not found
      {
        ferrum_log_debug("rule not found %s\n", dns->state.authz_id);
        write_activity_log(protocol, pair, dns, FERRUM_DNS_STATUS_ALLOW, FERRUM_FQDN_CATEGORY_UNKNOWN, NULL);
        result = send_client_directly(protocol, dns->state.reply_buf, dns->state.reply_buf_len);
        return result;
      }
      // ignore check
      char *fqdns = NULL;
      char *lists = NULL;
      result = db_get_authz_fqdn_intelligence(authz->content, "ignore", &fqdns, &lists);
      if (result) {
        ferrum_log_debug("fqdn ignore list parse failed authz:%s error:%d\n", dns->state.authz_id, result);
        ferrum_authz_db_authz_row_destroy(authz);
        write_activity_log(protocol, pair, dns, FERRUM_DNS_STATUS_ERROR, FERRUM_FQDN_CATEGORY_UNKNOWN, NULL);
        result = send_client_directly(protocol, dns->state.reply_buf, dns->state.reply_buf_len);
        return result;
      }
      char *founded;
      if (rebrick_util_fqdn_includes(fqdns, dns->query, ",", &founded) ||
          rebrick_util_fqdn_includes(lists, dns->state.redis_response, ",", &founded)) {
        ferrum_log_debug("fqdn %s found in ignore fqdns authz:%s \n", dns->query, dns->state.authz_id);
        rebrick_free_if_not_null_and_set_null(fqdns);
        rebrick_free_if_not_null_and_set_null(lists);
        rebrick_free_if_not_null_and_set_null(founded);
        ferrum_authz_db_authz_row_destroy(authz);
        // dont write log
        result = send_client_directly(protocol, dns->state.reply_buf, dns->state.reply_buf_len);
        return result;
      }
      // white list
      rebrick_free_if_not_null_and_set_null(fqdns);
      rebrick_free_if_not_null_and_set_null(lists);
      result = db_get_authz_fqdn_intelligence(authz->content, "white", &fqdns, &lists);
      if (result) {
        ferrum_log_debug("fqdn ignore list parse failed authz:%s error:%d\n", dns->state.authz_id, result);
        ferrum_authz_db_authz_row_destroy(authz);
        write_activity_log(protocol, pair, dns, FERRUM_DNS_STATUS_ERROR, FERRUM_FQDN_CATEGORY_UNKNOWN, NULL);
        result = send_client_directly(protocol, dns->state.reply_buf, dns->state.reply_buf_len);
        return result;
      }

      if (rebrick_util_fqdn_includes(fqdns, dns->query, ",", &founded) ||
          rebrick_util_fqdn_includes(lists, dns->state.redis_response, ",", &founded)) {
        ferrum_log_debug("fqdn %s found in white fqdns authz:%s \n", dns->query, dns->state.authz_id);
        rebrick_free_if_not_null_and_set_null(fqdns);
        rebrick_free_if_not_null_and_set_null(lists);
        write_activity_log(protocol, pair, dns, FERRUM_DNS_STATUS_ALLOW, FERRUM_FQDN_CATEGORY_WHITE_LIST, founded);
        rebrick_free_if_not_null_and_set_null(founded);
        ferrum_authz_db_authz_row_destroy(authz);
        result = send_client_directly(protocol, dns->state.reply_buf, dns->state.reply_buf_len);
        return result;
      }
      // black list
      rebrick_free_if_not_null_and_set_null(fqdns);
      rebrick_free_if_not_null_and_set_null(lists);
      result = db_get_authz_fqdn_intelligence(authz->content, "black", &fqdns, &lists);
      if (result) {
        ferrum_log_debug("fqdn ignore list parse failed authz:%s error:%d\n", dns->state.authz_id, result);
        ferrum_authz_db_authz_row_destroy(authz);
        write_activity_log(protocol, pair, dns, FERRUM_DNS_STATUS_ERROR, FERRUM_FQDN_CATEGORY_UNKNOWN, NULL);
        result = send_client_directly(protocol, dns->state.reply_buf, dns->state.reply_buf_len);
        return result;
      }

      if (rebrick_util_fqdn_includes(fqdns, dns->query, ",", &founded) ||
          rebrick_util_fqdn_includes(lists, dns->state.redis_response, ",", &founded)) {
        ferrum_log_debug("fqdn %s found in black fqdns authz:%s \n", dns->query, dns->state.authz_id);
        rebrick_free_if_not_null_and_set_null(fqdns);
        rebrick_free_if_not_null_and_set_null(lists);
        write_activity_log(protocol, pair, dns, FERRUM_DNS_STATUS_DENY, FERRUM_FQDN_CATEGORY_BLACK_LIST, founded);

        // TODO send client blockpage ip
        rebrick_free_if_not_null_and_set_null(founded);
        ferrum_authz_db_authz_row_destroy(authz);
        result = reply_dns_ip(pair, dns, "0.0.0.0", 300);
        return result;
      }
      rebrick_free_if_not_null_and_set_null(fqdns);
      rebrick_free_if_not_null_and_set_null(lists);
      ferrum_authz_db_authz_row_destroy(authz);

      write_activity_log(protocol, pair, dns, FERRUM_DNS_STATUS_ALLOW, FERRUM_FQDN_CATEGORY_UNKNOWN, founded);

      //  TODO remove if cname response A record ?? think about it
      // check AR records categories
      // filter categories

      result = send_client_directly(protocol, dns->state.reply_buf, dns->state.reply_buf_len);
      return result;
    }
  }
  return FERRUM_SUCCESS;
}

void redis_callback_lists(redisAsyncContext *context, void *_reply, void *_privdata) {
  ferrum_redis_t *redis = cast(context->data, ferrum_redis_t *);
  ferrum_redis_cmd_t *cmd = cast(_privdata, ferrum_redis_cmd_t *);
  ferrum_redis_reply_t *reply = cast(_reply, ferrum_redis_reply_t *);
  ferrum_protocol_t *protocol = cmd->callback.arg1;
  ferrum_raw_udpsocket_pair_t *pair = cmd->callback.arg2;
  ferrum_dns_packet_t *packet = cmd->callback.arg3;
  ferrum_redis_dns_query_t *rquery = cmd->callback.arg4;
  unused(packet);
  unused(redis);
  unused(cmd);
  unused(reply);
  unused(protocol);
  unused(pair);
  unused(rquery);
  if (!reply) { // timeout
    packet->state.is_redis_query_error = TRUE;
  } else if (reply->type == REDIS_REPLY_ERROR) {
    packet->state.is_redis_query_error = TRUE;
  } else if (reply->type == REDIS_REPLY_ARRAY) {
    size_t pos = 0;
    for (size_t i = 0; i < reply->elements; ++i) {
      size_t len = strlen(reply->element[i]->str);
      if (!packet->state.redis_response) {
        packet->state.redis_response = rebrick_malloc(len + 3);
        snprintf(packet->state.redis_response + pos, len + 3, ",%s,", reply->element[i]->str);
        pos += len + 2;
      } else {
        packet->state.redis_response = rebrick_realloc(packet->state.redis_response, pos + len + 2);
        snprintf(packet->state.redis_response + pos, len + 2, "%s,", reply->element[i]->str);
        pos += len + 1;
      }
    }
  }
  packet->state.is_redis_query_received = 1;
  ferrum_redis_cmd_destroy(cmd);
  process_dns_state(protocol, pair, packet);
  ferrum_dns_packet_destroy(packet);
}

int32_t send_redis_intel_lists(ferrum_protocol_t *protocol, ferrum_raw_udpsocket_pair_t *pair, ferrum_dns_packet_t *dns) {

  if (!dns->query || !dns->query[0])
    return FERRUM_ERR_BAD_ARGUMENT;
  if (!dns->state.redis_query_list_len)
    return FERRUM_ERR_BAD_ARGUMENT;

  if (dns->state.is_redis_query_sended)
    return FERRUM_SUCCESS;

  int32_t result;
  int32_t error_count = 0;
  size_t received_count = 0;
  int32_t query_index = -1;

  for (size_t i = 0; i < dns->state.redis_query_list_len; ++i) {
    ferrum_redis_dns_query_t *q = dns->state.redis_query_list + i;
    if (q->is_key_received) {
      received_count++;
    }
    if (q->is_error || q->is_key_timeout) {
      error_count++;
    }
    if (q->is_key_exists) {
      query_index = i;
      if (error_count == 0 && received_count == i + 1)
        break;
    }
  }
  if (error_count) { // no need to continue
    ferrum_log_debug("redis key search error\n");
    dns->state.is_redis_query_error = TRUE;
    process_dns_state(protocol, pair, dns);
    return FERRUM_SUCCESS;
  }
  if (received_count == dns->state.redis_query_list_len && query_index == -1) { // no key found
    ferrum_log_debug("redis key search not founded\n");
    dns->state.is_redis_query_not_found = TRUE;
    process_dns_state(protocol, pair, dns);
    return FERRUM_SUCCESS;
  }
  if (query_index <= -1) { // no error and not finished yet
    ferrum_log_debug("redis key search not finished yet\n");
    return FERRUM_SUCCESS;
  }
  dns->state.is_redis_query_sended = TRUE;

  ferrum_redis_dns_query_t *q = dns->state.redis_query_list + query_index;
  ferrum_log_debug("redis key search founded %s\n", q->query);

  ferrum_redis_cmd_t *cmd;
  result = ferrum_redis_cmd_new4(&cmd, redis_counter++, 0, redis_callback_lists, protocol, pair, dns, q);
  if (result) {
    ferrum_log_error("redis cmd create failed %d\n", result);
    q->is_error = TRUE;
    dns->state.is_redis_query_error = TRUE;
    process_dns_state(protocol, pair, dns);
    return FERRUM_SUCCESS;
  }
  char cmd_str[1024] = {0};
  snprintf(cmd_str, sizeof(cmd_str) - 1, "smembers /fqdn/%s/list", q->query);
  result = ferrum_redis_send(cast(protocol->redis_intel, ferrum_redis_t *), cmd, cmd_str);
  if (result) {
    ferrum_log_error("redis query send failed\n", result);
    ferrum_redis_cmd_destroy(cmd);
    dns->state.is_redis_query_error = TRUE;
    process_dns_state(protocol, pair, dns);
    return FERRUM_SUCCESS;
  }
  q->is_lists_sended = TRUE;
  ferrum_dns_packet_ref_increment(dns);

  return FERRUM_SUCCESS;
}

void redis_callback_key_is_exists(redisAsyncContext *context, void *_reply, void *_privdata) {
  ferrum_redis_t *redis = cast(context->data, ferrum_redis_t *);
  ferrum_redis_cmd_t *cmd = cast(_privdata, ferrum_redis_cmd_t *);
  ferrum_redis_reply_t *reply = cast(_reply, ferrum_redis_reply_t *);
  ferrum_protocol_t *protocol = cmd->callback.arg1;
  ferrum_raw_udpsocket_pair_t *pair = cmd->callback.arg2;
  ferrum_dns_packet_t *packet = cmd->callback.arg3;
  ferrum_redis_dns_query_t *rquery = cmd->callback.arg4;
  unused(packet);
  unused(redis);
  unused(cmd);
  unused(reply);
  unused(protocol);
  unused(pair);
  if (!reply) { // timeout
    rquery->is_key_timeout = 1;
  } else if (reply->type == REDIS_REPLY_ERROR) {
    rquery->is_error = 1;
  } else if (reply->type == REDIS_REPLY_INTEGER) {
    rquery->is_key_exists = reply->integer;
  }
  rquery->is_key_received = 1;
  ferrum_redis_cmd_destroy(cmd);
  send_redis_intel_lists(protocol, pair, packet);
  ferrum_dns_packet_destroy(packet);
}

int32_t send_redis_intel(ferrum_protocol_t *protocol, ferrum_raw_udpsocket_pair_t *pair, ferrum_dns_packet_t *dns) {

  if (!dns->query || !dns->query[0])
    return FERRUM_ERR_BAD_ARGUMENT;
  ferrum_redis_dns_query_t *rqueries;
  size_t rqueries_len = 0;
  int32_t result = split_fqdn_for_redis(dns->query, &rqueries, &rqueries_len);

  if (result || !rqueries_len) {
    ferrum_log_error("redis key search create failed %d\n", result);
    return FERRUM_ERR_BAD_ARGUMENT;
  }
  dns->state.redis_query_list = rqueries;
  dns->state.redis_query_list_len = rqueries_len;

  for (size_t i = 0; i < rqueries_len; ++i) {
    ferrum_redis_dns_query_t *q = rqueries + i;
    ferrum_redis_cmd_t *cmd;
    result = ferrum_redis_cmd_new4(&cmd, redis_counter++, 0, redis_callback_key_is_exists, protocol, pair, dns, q);
    if (result) {
      ferrum_log_error("redis cmd create failed %d\n", result);
      q->is_error = TRUE;
      continue;
    }
    char cmd_str[1024] = {0};
    snprintf(cmd_str, sizeof(cmd_str) - 1, "EXISTS /fqdn/%s/list", q->query);
    result = ferrum_redis_send(cast(protocol->redis_intel, ferrum_redis_t *), cmd, cmd_str);
    if (result) {
      ferrum_log_error("redis key search send failed\n", result);
      ferrum_redis_cmd_destroy(cmd);
      q->is_error = TRUE;
      continue;
    }
    q->is_key_sended = TRUE;
    ferrum_dns_packet_ref_increment(dns);
  }

  return FERRUM_SUCCESS;
}

int32_t reply_local_dns(ferrum_protocol_t *protocol, ferrum_raw_udpsocket_pair_t *pair, ferrum_dns_packet_t *dns) {
  int32_t result;
  if (dns->query_type == LDNS_RR_TYPE_AAAA) { // return nx
    result = reply_dns_empty(pair, dns, LDNS_RCODE_NXDOMAIN);
    return result;
  } else if (dns->query_type == LDNS_RR_TYPE_A) { // check root fqdn ip address
    char ip[REBRICK_IP_STR_LEN] = {0};
    result = ferrum_dns_db_find_local_a(protocol->dns_db, dns->query, ip);
    if (result) { // error, return error
      result = reply_dns_empty(pair, dns, LDNS_RCODE_SERVFAIL);
      return result;
    } else if (!ip[0]) { // nx result
      result = reply_dns_empty(pair, dns, LDNS_RCODE_NXDOMAIN);
      return result;
    } else {
      result = reply_dns_ip(pair, dns, ip, 300);
      return result;
    }
  } else
    result = reply_dns_empty(pair, dns, LDNS_RCODE_NXDOMAIN);
  return result;
}

int32_t db_get_authz_fqdn_intelligence(char *content, const char *name, char **fqdns, char **lists) {
  *fqdns = NULL;
  *lists = NULL;

  if (!content || !name)
    return FERRUM_SUCCESS;
  char errbuf[200] = {0};
  toml_table_t *conf = toml_parse(content, errbuf, sizeof(errbuf));
  if (!conf) {
    ferrum_log_error("authz ignore fqdn parse error %s\n", errbuf);
    return FERRUM_ERR_AUTHZ_DB_PARSE;
  }
  toml_table_t *fqdnIntelligence = toml_table_in(conf, "fqdnIntelligence");
  if (!fqdnIntelligence) {
    ferrum_log_debug("authz ignore fqdnIntelligence not found %s\n", errbuf);
    toml_free(conf);
    return FERRUM_SUCCESS;
  }
  char path[32] = {0};
  snprintf(path, sizeof(path) - 1, "%sFqdns", name);
  toml_datum_t ignorelist = toml_string_in(fqdnIntelligence, path);
  if (ignorelist.ok) {
    *fqdns = ignorelist.u.s;
  }
  snprintf(path, sizeof(path) - 1, "%sLists", name);
  ignorelist = toml_string_in(fqdnIntelligence, path);
  if (ignorelist.ok) {
    *lists = ignorelist.u.s;
  }

  // toml_free(fqdnIntelligence);
  toml_free(conf);
  return FERRUM_SUCCESS;
}

static int32_t process_input_udp(ferrum_protocol_t *protocol, const uint8_t *buffer, size_t len) {
  unused(protocol);
  unused(buffer);
  unused(len);

  ferrum_raw_udpsocket_pair_t *pair = protocol->pair.udp;

  ferrum_dns_packet_new(dns);
  int32_t result = ferrum_dns_packet_from(buffer, len, dns);
  if (result) { // parse problem #test 1
    rebrick_log_error("input dns packet parse error %d\n", result);
    // drop silently
    ferrum_dns_packet_destroy(dns);
    return FERRUM_ERR_DNS_BAD_PACKET;
  }

  // check if query ends with our root domain
  // no log #test2
  if (rebrick_util_fqdn_endswith(dns->query, protocol->config->root_fqdn)) {
    result = reply_local_dns(protocol, pair, dns);
    ferrum_dns_packet_destroy(dns);
    return result;
  }

  // we dont care queries out ot AAAA and A, #test3
  if (dns->query_type != LDNS_RR_TYPE_AAAA && dns->query_type != LDNS_RR_TYPE_A) {
    result = send_backend_directly(protocol, pair, dns, buffer, len);
    ferrum_dns_packet_destroy(dns);
    return result;
  }

  // get user and group ids
  result = db_get_user_and_group_ids(protocol, pair->mark);
  if (result) { // #test4
    rebrick_log_error("get user and group ids failed %d\n", result);
    write_activity_log(protocol, pair, dns, FERRUM_DNS_STATUS_ERROR, FERRUM_FQDN_CATEGORY_UNKNOWN, NULL);
    reply_dns_empty(pair, dns, LDNS_RCODE_SERVFAIL); // we must send servfail
    ferrum_dns_packet_destroy(dns);
    return result;
  }
  if (!protocol->identity.user_id && !protocol->identity.group_ids) // we dont know user and group,interesting situation, #test5
  {
    write_activity_log(protocol, pair, dns, FERRUM_DNS_STATUS_INVALID, FERRUM_FQDN_CATEGORY_UNKNOWN, NULL);
    result = send_backend_directly(protocol, pair, dns, buffer, len);
    ferrum_dns_packet_destroy(dns);
    return result;
  }
  // we know user and groups now

  // find service related authz users and groups
  ferrum_authz_db_service_user_row_t *authz_users = NULL;
  result = ferrum_authz_db_get_service_user_data(protocol->authz_db, protocol->config->service_id, &authz_users);
  if (result) { // #test6
    ferrum_log_error("authz db get service failed with error:%d\n", result);
    // reply_dns_empty(pair, dns, LDNS_RCODE_SERVFAIL);
    write_activity_log(protocol, pair, dns, FERRUM_DNS_STATUS_ERROR, FERRUM_FQDN_CATEGORY_UNKNOWN, NULL);
    result = send_backend_directly(protocol, pair, dns, buffer, len);
    ferrum_dns_packet_destroy(dns);
    return result;
  }
  if (!authz_users) { // no user or group found for this service in authz, probably there is a problem, #test 7
    ferrum_log_debug("authz db user not found\n");
    write_activity_log(protocol, pair, dns, FERRUM_DNS_STATUS_INVALID, FERRUM_FQDN_CATEGORY_UNKNOWN, NULL);
    result = send_backend_directly(protocol, pair, dns, buffer, len);
    ferrum_authz_db_service_user_row_destroy(authz_users);
    ferrum_dns_packet_destroy(dns);
    return result;
  }
  // find match rule
  const char *authz_id = NULL;
  for (size_t i = 0; i < authz_users->rows_len; ++i) {
    ferrum_authz_service_user_data_t *udata = authz_users->rows + i;
    char *founded;
    if (udata->user_or_group_ids &&
        (!strcmp(udata->user_or_group_ids, ",,") ||
         rebrick_util_str_includes(udata->user_or_group_ids, protocol->identity.user_id, ",", &founded) ||
         rebrick_util_str_includes(udata->user_or_group_ids, protocol->identity.group_ids, ",", &founded))) {
      authz_id = udata->authz_id;
      rebrick_free_if_not_null_and_set_null(founded); // important
      rebrick_log_debug("authz user founded for rule %s\n", authz_id);
      break;
    }
  }
  if (!authz_id) { // no rule match #test 8
    ferrum_log_debug("no rule to match\n", result);
    write_activity_log(protocol, pair, dns, FERRUM_DNS_STATUS_INVALID, FERRUM_FQDN_CATEGORY_UNKNOWN, NULL);
    result = send_backend_directly(protocol, pair, dns, buffer, len);
    ferrum_authz_db_service_user_row_destroy(authz_users);
    ferrum_dns_packet_destroy(dns);
    return result;
  }
  dns->state.authz_id = strdup(authz_id);
  // dont use authz_id anymore
  ferrum_authz_db_service_user_row_destroy(authz_users);

  // get auth rule
  ferrum_authz_db_authz_row_t *authz = NULL;
  result = ferrum_authz_db_get_authz_data(protocol->authz_db, dns->state.authz_id, &authz);
  if (result) { // no way to test this
    ferrum_log_error("authz db get authz failed with error:%d\n", result);
    // reply_dns_empty(pair, dns, LDNS_RCODE_SERVFAIL);
    write_activity_log(protocol, pair, dns, FERRUM_DNS_STATUS_ERROR, FERRUM_FQDN_CATEGORY_UNKNOWN, NULL);
    result = send_backend_directly(protocol, pair, dns, buffer, len);
    ferrum_dns_packet_destroy(dns);
    return result;
  }
  if (!authz) // rule not found #test 9x
  {
    ferrum_log_debug("rule not found %s\n", dns->state.authz_id);
    write_activity_log(protocol, pair, dns, FERRUM_DNS_STATUS_INVALID, FERRUM_FQDN_CATEGORY_UNKNOWN, NULL);
    result = send_backend_directly(protocol, pair, dns, buffer, len);
    ferrum_dns_packet_destroy(dns);
    return result;
  }

  char *ignore_fqdns = NULL;
  char *ignore_lists = NULL;
  result = db_get_authz_fqdn_intelligence(authz->content, "ignore", &ignore_fqdns, &ignore_lists);
  if (result) { // test 10x
    ferrum_log_debug("fqdn ignore list parse failed authz:%s error:%d\n", dns->state.authz_id, result);
    write_activity_log(protocol, pair, dns, FERRUM_DNS_STATUS_ERROR, FERRUM_FQDN_CATEGORY_UNKNOWN, NULL);
    ferrum_authz_db_authz_row_destroy(authz);
    result = send_backend_directly(protocol, pair, dns, buffer, len);
    ferrum_dns_packet_destroy(dns);
    return result;
  }
  ferrum_authz_db_authz_row_destroy(authz);

  char *founded;
  if (rebrick_util_fqdn_includes(ignore_fqdns, dns->query, ",", &founded)) { // #test 11x
    ferrum_log_debug("fqdn %s found in ignore list authz:%s \n", dns->query, dns->state.authz_id);
    rebrick_free_if_not_null_and_set_null(ignore_fqdns);
    rebrick_free_if_not_null_and_set_null(ignore_lists);
    rebrick_free_if_not_null_and_set_null(founded);
    // dont log
    result = send_backend_directly(protocol, pair, dns, buffer, len);
    ferrum_dns_packet_destroy(dns);
    return result;
  }

  rebrick_free_if_not_null_and_set_null(ignore_fqdns);
  rebrick_free_if_not_null_and_set_null(ignore_lists);
  result = send_redis_intel(protocol, pair, dns); // dont care if fails
  if (result) {                                   // sending redis and backend failed
    result = send_backend_directly(protocol, pair, dns, buffer, len);
    ferrum_dns_packet_destroy(dns);
    return result;
  }
  // add to cache, everything is going on well
  dns->source = pair->client_addr;
  dns->destination = pair->udp_destination_addr;
  cast_to_dns_data_var(protocol->data, data);
  result = ferrum_dns_cache_add(data->cache, dns);
  if (result) {
    ferrum_dns_packet_destroy(dns);
  }
  result = send_backend_directly(protocol, pair, dns, buffer, len);
  // dont care result;

  return result;
}

static int32_t send_client_directly(ferrum_protocol_t *protocol, const uint8_t *buffer, size_t len) {

  ferrum_raw_udpsocket_pair_t *pair = protocol->pair.udp;
  uint8_t *buf = rebrick_malloc(len);
  if_is_null_then_die(buf, "malloc problem\n");
  memcpy(buf, buffer, len);
  new2(rebrick_clean_func_t, clean_func);
  clean_func.func = free_memory;
  clean_func.ptr = buf;

  int32_t result = rebrick_udpsocket_write(pair->udp_listening_socket, &pair->client_addr, buf, len, clean_func);
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
  ferrum_dns_packet_new(rdns);
  int32_t result = ferrum_dns_packet_from(buffer, len, rdns);
  if (result) {
    // drop silently
    rebrick_log_error("output dns packet parse failed %d\n", result);
    ferrum_dns_packet_destroy(rdns);
    return FERRUM_ERR_DNS_BAD_PACKET;
  }
  if (!rdns->query || !rdns->query[0]) {
    rebrick_log_error("output dns packet not normal %d\n", result);
    ferrum_dns_packet_destroy(rdns);
    return FERRUM_ERR_DNS_BAD_PACKET;
  }
  // only A and AAAA
  if (rdns->query_type != LDNS_RR_TYPE_A && rdns->query_type != LDNS_RR_TYPE_AAAA) {
    ferrum_dns_packet_destroy(rdns);
    send_client_directly(protocol, buffer, len);
    return FERRUM_SUCCESS;
  }

  ferrum_raw_udpsocket_pair_t *pair = protocol->pair.udp;
  rdns->source = pair->udp_destination_addr;
  rdns->destination = pair->client_addr;

  cast_to_dns_data_var(protocol->data, data);
  ferrum_dns_cache_founded_t *cache_item;
  result = ferrum_dns_cache_find(data->cache, rdns, &cache_item);
  if (result) {
    rebrick_log_error("dns query cache failed %s %d\n", rdns->query, result);
    ferrum_dns_packet_destroy(rdns);
    // TODO log
    send_client_directly(protocol, buffer, len);
    return FERRUM_SUCCESS;
  }
  if (!cache_item->dns) { // query dns data not founded
    rebrick_log_debug("dns query cache not found %s %d\n", rdns->query, result);
    ferrum_dns_packet_destroy(rdns);
    ferrum_dns_cache_remove_founded(data->cache, cache_item);
    // TODO log
    send_client_directly(protocol, buffer, len);
    return FERRUM_SUCCESS;
  }
  rebrick_log_debug("dns query cache found %s\n", rdns->query);
  ferrum_dns_packet_t *qdns = cache_item->dns;
  qdns->state.is_backend_received = TRUE;

  qdns->state.reply_buf = rebrick_malloc(len);
  qdns->state.reply_buf_len = len;
  if_is_null_then_die(qdns->state.reply_buf, "malloc problem\n");
  memcpy(qdns->state.reply_buf, buffer, len);
  result = process_dns_state(protocol, pair, qdns);

  ferrum_dns_cache_remove(data->cache, cache_item);
  ferrum_dns_packet_destroy(rdns);
  // dont care result

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
      rebrick_free(protocol->data);
    }
    if (protocol->identity.user_id)
      rebrick_free(protocol->identity.user_id);
    if (protocol->identity.group_ids)
      rebrick_free(protocol->identity.group_ids);
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
  int32_t result = ferrum_dns_cache_new(&cache, 5000);
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
