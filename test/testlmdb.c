#include "./rebrick/common/rebrick_common.h"
#include "./rebrick/server_client/udpecho.h"
#include "./rebrick/server_client/tcpecho.h"
#include "./rebrick/common/rebrick_util.h"
#include "./ferrum/ferrum_lmdb.h"

#include "cmocka.h"
#include <unistd.h>

int main(int argc, char **args) {
  unused(argc);
  fprintf(stdout, "starting test\n");
  rebrick_log_level(REBRICK_LOG_ALL);
  ferrum_lmdb_t *lmdb;
  int32_t result = ferrum_lmdb_new(&lmdb, args[1], args[2], 0, 0);
  if (result) {
    fprintf(stderr, "failed to open lmdb\n");
    exit(1);
  }
  if (!strcmp(args[3], "put")) {
    lmdb->root->key.size = snprintf(lmdb->root->key.val, sizeof(lmdb->root->key) - 1, "%s", args[4]);
    lmdb->root->value.size = snprintf(lmdb->root->value.val, sizeof(lmdb->root->value) - 1, "%s", args[5]);
    ferrum_lmdb_put(lmdb, &lmdb->root->key, &lmdb->root->value);
    fprintf(stdout, "ok\n");
  }
  if (!strcmp(args[3], "get")) {
    lmdb->root->key.size = snprintf(lmdb->root->key.val, sizeof(lmdb->root->key) - 1, "%s", args[4]);
    ferrum_lmdb_get(lmdb, &lmdb->root->key, &lmdb->root->value);
    if (lmdb->root->value.size) {
      fprintf(stdout, "%s\n", lmdb->root->value.val);
    }
  }
  if (!strcmp(args[3], "del")) {
    lmdb->root->key.size = snprintf(lmdb->root->key.val, sizeof(lmdb->root->key) - 1, "%s", args[4]);
    ferrum_lmdb_del(lmdb, &lmdb->root->key);
    fprintf(stdout, "ok\n");
  }
  if (!strcmp(args[3], "list")) {

    ferrum_lmdb_list_all(lmdb);
  }

  return 0;
}