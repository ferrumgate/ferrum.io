#ifndef __REBRICK_TLS_H__
#define __REBRICK_TLS_H__

#include "./rebrick_common.h"
#include "./rebrick_log.h"
#include "./lib/uthash.h"
#include "./lib/utlist.h"

struct rebrick_async_tlssocket;

typedef void (*rebrick_tls_checkitem_func)(struct rebrick_async_tlssocket *socket);

typedef struct rebrick_tls_checkitem{
    base_object();
    public_ readonly_ struct rebrick_async_tlssocket *socket;
    public_ readonly_ rebrick_tls_checkitem_func func;
    private_ struct rebrick_tls_checkitem *prev;
    private_ struct rebrick_tls_checkitem *next;
}rebrick_tls_checkitem_t;


typedef struct rebrick_tls_checkitem_list{
    base_object();
    public_ rebrick_tls_checkitem_t *head;
}rebrick_tls_checkitem_list_t;

/**
 * @brief after io, and before io check list
 * singleton pattern
 *
 */
rebrick_tls_checkitem_list_t *tls_after_io_checklist;
rebrick_tls_checkitem_list_t *tls_before_io_checklist;

int32_t rebrick_after_io_list_add(rebrick_tls_checkitem_func func,struct rebrick_async_tlssocket *socket);
int32_t rebrick_after_io_list_remove(struct rebrick_async_tlssocket *socket);
int32_t rebrick_before_io_list_add(rebrick_tls_checkitem_func func,struct rebrick_async_tlssocket *socket);
int32_t rebrick_before_io_list_remove(struct rebrick_async_tlssocket *socket);


/**
 * @brief inits tls
 *
 * @return int32_t REBRICK_SUCCESS
 */
int32_t rebrick_tls_init();





typedef struct rebrick_tls_context{
    base_object();
    private_ char key[REBRICK_TLS_KEY_LEN];
    public_ readonly_  SSL_CTX * tls_ctx;
    public_ readonly_ int32_t is_server;
    private_ const char ca_verify_path[REBRICK_CA_VERIFY_PATH_MAX_LEN];

}rebrick_tls_context_t;



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
int32_t rebrick_tls_context_new(rebrick_tls_context_t **context,const char *key,int32_t ssl_verify,int32_t session_mode,int32_t options,const char *certificate_file,const char *private_file);
int32_t rebrick_tls_context_destroy(rebrick_tls_context_t *context);

/**
 * @brief returns context if its finds otherwise returns null
 *
 * @param key  search key
 * @param context destination context ptr_ptr
 * @return int32_t returns REBRICK_SUCCESS else error
 */
int32_t rebrick_tls_context_get(const char *key,rebrick_tls_context_t **context);



typedef struct rebrick_tls_ssl{
    base_object();
    public_ readonly_ SSL *ssl;
    public_ readonly_ BIO *read;
    public_ readonly_ BIO *write;

}rebrick_tls_ssl_t;

/**
 * @brief creates a new ssl
 *
 * @param ssl
 * @param context checks this context and if context is server then SSL is server otherwise client
 * @return int32_t
 */
int32_t rebrick_tls_ssl_new(rebrick_tls_ssl_t **ssl,const rebrick_tls_context_t *context);
int32_t rebrick_tls_ssl_destroy(rebrick_tls_ssl_t *ssl);

#endif