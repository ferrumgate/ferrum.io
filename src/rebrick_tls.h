#ifndef __REBRICK_TLS_H__
#define __REBRICK_TLS_H__

#include "./rebrick_common.h"
#include "./rebrick_log.h"
#include "./lib/uthash.h"


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

}rebrick_tls_context_t;

typedef struct rebrick_tls{
    base_object();


}rebrick_tls_t;

/**
 * @brief creates a new context if is absent in hash map with key
 *
 * @param context
 * @param key hash key
 * @param ssl_verify
 * @param session_mode
 * @param options
 * @param certificate_file
 * @param private_file
 * @return int32_t return REBRICK_SUCCESS  <0 means error
 */
int32_t rebrick_tls_context_new(rebrick_tls_context_t **context,const char *key, int32_t ssl_verify,int32_t session_mode,int32_t options,const char *certificate_file,const char *private_file);
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