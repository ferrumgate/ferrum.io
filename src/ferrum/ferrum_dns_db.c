#include "ferrum_dns_db.h"
int32_t ferrum_dns_db_new(ferrum_dns_db_t **dns, ferrum_config_t *config) {
  int32_t result;
  ferrum_lmdb_t *lmdb;
  const char *db_folder = config->db_folder[0] ? config->db_folder : config->dns_db_folder;
  result = ferrum_lmdb_new(&lmdb, db_folder, "dns", 24, 1073741824);
  if (result)
    return result;
  ferrum_log_info("dns lmdb folder:%s\n", db_folder);

  ferrum_dns_db_t *tmp = new1(ferrum_dns_db_t);
  if (!tmp) {
    ferrum_log_fatal("malloc problem\n");
    rebrick_kill_current_process(REBRICK_ERR_MALLOC);
  }
  constructor(tmp, ferrum_dns_db_t);
  tmp->config = config;
  tmp->lmdb = lmdb;
  *dns = tmp;
  return FERRUM_SUCCESS;
}
int32_t ferrum_dns_db_destroy(ferrum_dns_db_t *dns) {
  if (dns) {
    if (dns->lmdb) {
      ferrum_lmdb_destroy(dns->lmdb);
      dns->lmdb = NULL;
    }
    rebrick_free(dns);
  }
  return FERRUM_SUCCESS;
}

int32_t ferrum_dns_db_find_local_a(const ferrum_dns_db_t *dns, const char *fqdn, char ip[REBRICK_IP_STR_LEN]) {

  ferrum_lmdb_t *lmdb = dns->lmdb;
  lmdb->root->key.size = snprintf(lmdb->root->key.val, sizeof(lmdb->root->key.val) - 1, "/local/dns/%s/a", fqdn);
  int32_t result = ferrum_lmdb_get(lmdb, &lmdb->root->key, &lmdb->root->value);
  if (result) {
    if (result == FERRUM_ERR_LMDB) {
      ferrum_log_debug("query local dns %s error:%d\n", fqdn, result);
      return FERRUM_ERR_DNS_DB;
    }
    ferrum_log_debug("query local dns %s not found\n", fqdn);
    // ferrum_lmdb_list_all(lmdb);
    return FERRUM_SUCCESS; // ip is empty
  }
  if (lmdb->root->value.size) {
    size_t min = MIN(lmdb->root->value.size, REBRICK_IP_STR_LEN - 1);
    memcpy(ip, lmdb->root->value.val, min);
    ferrum_log_debug("query local dns %s ip:%s\n", fqdn, ip);
  }
  return FERRUM_SUCCESS;
}