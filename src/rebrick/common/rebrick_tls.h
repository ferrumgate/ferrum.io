#ifndef __REBRICK_TLS_H__
#define __REBRICK_TLS_H__

#include "./rebrick_common.h"
#include "./rebrick_log.h"
#include "../lib/uthash.h"
#include "../lib/utlist.h"

#define REBRICK_TLS_SNI_MAX_LEN 1024
#define REBRICK_TLS_CONTEXT_SNI "CTX_SNI"
#define REBRICK_TLS_FILE_MAX_LEN 1024
#define REBRICK_TLS_SNI_FAKE_CERT_PRV_FILE "/tmp/nofile"

struct rebrick_tlssocket;

typedef void (*rebrick_tls_checkitem_func)(struct rebrick_tlssocket *socket);

typedef struct rebrick_tls_checkitem {
  base_object();
  public_ readonly_ struct rebrick_tlssocket *socket;
  public_ readonly_ rebrick_tls_checkitem_func func;
  private_ struct rebrick_tls_checkitem *prev;
  private_ struct rebrick_tls_checkitem *next;
} rebrick_tls_checkitem_t;

typedef struct rebrick_tls_checkitem_list {
  base_object();
  public_ rebrick_tls_checkitem_t *head;
} rebrick_tls_checkitem_list_t;

/**
 * @brief after io, and before io check list
 * singleton pattern
 *
 */
rebrick_tls_checkitem_list_t *tls_after_io_checklist;
rebrick_tls_checkitem_list_t *tls_before_io_checklist;

int32_t rebrick_after_io_list_add(rebrick_tls_checkitem_func func, struct rebrick_tlssocket *socket);
int32_t rebrick_after_io_list_remove(struct rebrick_tlssocket *socket);
int32_t rebrick_before_io_list_add(rebrick_tls_checkitem_func func, struct rebrick_tlssocket *socket);
int32_t rebrick_before_io_list_remove(struct rebrick_tlssocket *socket);

/**
 * @brief inits tls
 *
 * @return int32_t REBRICK_SUCCESS
 */
int32_t rebrick_tls_init();
int32_t rebrick_tls_cleanup();

struct rebrick_tls_ssl;

typedef int (*rebrick_tls_alpn_select_callback_t)(unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen);
typedef int (*rebrick_tls_npn_select_callback_t)(unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen);

typedef struct rebrick_tls_context {
  base_object();
  private_ char key[REBRICK_TLS_KEY_LEN];
  private_ char sni_pattern[REBRICK_TLS_SNI_MAX_LEN];
  public_ readonly_ SSL_CTX *tls_ctx;

  private_ const char ca_verify_path[REBRICK_CA_VERIFY_PATH_MAX_LEN];
  public_ readonly_ char cert_file[REBRICK_TLS_FILE_MAX_LEN];
  public_ readonly_ char prv_file[REBRICK_TLS_FILE_MAX_LEN];

  // this field is for list
  internal_ struct rebrick_tls_ssl *sni_pending_list;

  public_ readonly_ uint8_t alpn_protos[REBRICK_TLS_ALPN_MAX_LEN];
  public_ readonly_ size_t alpn_protos_len;

  internal_ rebrick_tls_alpn_select_callback_t alpn_select_callback;
  internal_ rebrick_tls_npn_select_callback_t npn_select_callback;

} rebrick_tls_context_t;

#define rebrick_tls_context_is_server(x) (strlen((x)->prv_file))

/**
 * @brief creates a new context if is absent in hash map with key
 *
 * @param context
 * @param key hash key
 * @param ca verify path
 * @param ssl_verify  SSL_VERIFY_NONE,SSL_VERIFY_PEER,SSL_VERIFY_FAIL_IF_NO_PEER_CERT,SSL_VERIFY_CLIENT_ONCE,SSL_VERIFY_POST_HANDSHAKE
 * @param session_mode  SSL_SESS_CACHE_OFF, SSL_SESS_CACHE_CLIENT,SSL_SESS_CACHE_SERVER,SSL_SESS_CACHE_BOTH
 * @param options SSL_OP_ALL, or vs... vs...
 * @param certificate_file NULL for client
 * @param private_file NULL for client
 * @return int32_t return REBRICK_SUCCESS,  <0 means error
 */
int32_t rebrick_tls_context_new(rebrick_tls_context_t **context, const char *key, int32_t ssl_verify, int32_t session_mode, int32_t options, int32_t clearoptions, const char *certificate_file, const char *private_file);
int32_t rebrick_tls_context_destroy(rebrick_tls_context_t *context);
int32_t rebrick_tls_context_set_alpn_protos(rebrick_tls_context_t *context, const unsigned char *protos, unsigned int protos_len, rebrick_tls_alpn_select_callback_t callback);
int32_t rebrick_tls_context_set_npn_protos(rebrick_tls_context_t *context, const unsigned char *protos, unsigned int protos_len, rebrick_tls_npn_select_callback_t callback);

/**
 * @brief returns context if its finds otherwise returns null and NOT_FOUND error
 *
 * @param key  search key
 * @param context destination context ptr_ptr
 * @return int32_t returns REBRICK_SUCCESS else error
 */
int32_t rebrick_tls_context_get(const char *key, rebrick_tls_context_t **context);
int32_t rebrick_tls_context_search(const char *servername, rebrick_tls_context_t **context);

typedef struct rebrick_tls_ssl {
  base_object();
  public_ readonly_ SSL *ssl;
  public_ readonly_ BIO *read;
  public_ readonly_ BIO *write;

  /**
   * @brief ref ptr to some data
   *
   */
  public_ readonly_ void *ref;

  /**
   * @brief fields for defining a list
   *
   */
  public_ readonly_ struct rebrick_tls_ssl *prev;
  public_ readonly_ struct rebrick_tls_ssl *next;

} rebrick_tls_ssl_t;

/**
 * @brief creates a new ssl from context
 *
 * @param ssl
 * @param context checks this context and if context is server then SSL is server otherwise client
 * @return int32_t
 */
int32_t rebrick_tls_ssl_new(rebrick_tls_ssl_t **ssl, const rebrick_tls_context_t *context);

/**
 * @brief for client creating with SNI
 *
 * @param ssl
 * @param context
 * @param servername SNI name
 * @return int32_t
 */
int32_t rebrick_tls_ssl_new3(rebrick_tls_ssl_t **ssl, const rebrick_tls_context_t *context, const char *servername);

/**
 * @brief creates a new ssl from server indication name
 *
 * @param ssl
 * @param server_indication_name
 * @return int32_t
 */
int32_t rebrick_tls_ssl_new2(rebrick_tls_ssl_t **ssl, const char *server_indication_name);
int32_t rebrick_tls_ssl_destroy(rebrick_tls_ssl_t *ssl);

#endif