#include "ferrum_dns.h"
int32_t ferrum_dns_new(ferrum_dns_t **dns, ferrum_config_t *config) {
  int32_t result;
  ferrum_lmdb_t *lmdb;
  result = ferrum_lmdb_new(&lmdb, config->dns_db_folder, "dns", 3, 1073741824);
  if (result)
    return result;

  ferrum_dns_t *tmp = new1(ferrum_dns_t);
  if (!tmp) {
    ferrum_log_fatal("malloc problem\n");
    rebrick_kill_current_process(REBRICK_ERR_MALLOC);
  }
  constructor(tmp, ferrum_dns_t);
  tmp->config = config;
  tmp->lmdb = lmdb;
  *dns = tmp;
  return FERRUM_SUCCESS;
}
int32_t ferrum_dns_destroy(ferrum_dns_t *dns) {
  if (dns) {
    if (dns->lmdb) {
      ferrum_lmdb_destroy(dns->lmdb);
      dns->lmdb = NULL;
    }
    rebrick_free(dns);
  }
  return FERRUM_SUCCESS;
}

int32_t ferrum_dns_find_local_a(const ferrum_dns_t *dns, char fqdn[FERRUM_DNS_MAX_FQDN_LEN], char ip[REBRICK_IP_STR_LEN]) {

  ferrum_lmdb_t *lmdb = dns->lmdb;
  lmdb->key.size = snprintf(lmdb->key.val, sizeof(lmdb->key.val) - 1, "/local/dns/%s/a", fqdn);
  int32_t result = ferrum_lmdb_get(lmdb, &lmdb->key, &lmdb->value);
  if (result) {
    if (result == FERRUM_ERR_LMDB)
      return FERRUM_ERR_DNS;
    return FERRUM_SUCCESS; // ip is empty
  }
  size_t min = MIN(lmdb->value.size, REBRICK_IP_STR_LEN - 1);
  memcpy(ip, lmdb->value.val, min);

  return FERRUM_SUCCESS;
}