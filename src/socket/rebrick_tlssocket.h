#ifndef __REBRICK_TLSSOCKET_H__
#define __REBRICK_TLSSOCKET_H__

#include "../common/rebrick_tls.h"
#include "./rebrick_tcpsocket.h"
#include "../common/rebrick_buffers.h"

/**
 * @brief openssl is an interesting library, that sometimes you need pending data
 *
 */
protected_ typedef struct pending_data
{
    base_object();
    rebrick_buffers_t *data;
    /**
     * @brief clean function
     *
     */
    rebrick_clean_func_t *clean_func;
    /**
     * @brief this fields prev and next means, this is a list
     *
     */
    struct pending_data *prev, *next;
} pending_data_t;

typedef void (*rebrick_tlssocket_on_sni_read_callback_t)(struct rebrick_socket *socket, void *callback_data, const char *sni);

#define base_ssl_socket()                                                    \
    base_tcp_socket();                                                       \
    private_ const rebrick_tls_context_t *tls_context;                       \
    private_ rebrick_tls_ssl_t *tls;                                         \
    private_ rebrick_tcpsocket_on_accept_callback_t override_on_accept;      \
    private_ rebrick_tcpsocket_on_close_callback_t override_on_client_close; \
    private_ rebrick_socket_on_read_callback_t override_on_read;             \
    private_ rebrick_socket_on_write_callback_t override_on_write;           \
    private_ rebrick_socket_on_error_callback_t override_on_error;           \
    private_ rebrick_tlssocket_on_sni_read_callback_t override_on_sni_read;  \
    private_ void *override_callback_data;                                   \
    private_ pending_data_t *pending_write_list;                             \
    private_ int32_t called_override_after_connection_accept;                \
    private_ int32_t sslhandshake_initted;                                   \
    public_ readonly_ char sni_pattern_or_name[REBRICK_TLS_SNI_MAX_LEN];     \
    public_ readonly_ char sni[REBRICK_TLS_SNI_MAX_LEN];

public_ typedef struct rebrick_tlssocket
{
    base_ssl_socket()

} rebrick_tlssocket_t;

#define cast_to_tlssocket(x) cast(x, rebrick_tlssocket_t *)

#define base_tlssocket_callbacks() \
    base_tcpsocket_callbacks();    \
    protected_ rebrick_tlssocket_on_sni_read_callback_t on_sni_received;

typedef struct rebrick_tlssocket_callbacks
{
    base_tlssocket_callbacks();
} rebrick_tlssocket_callbacks_t;

#define cast_to_tlssocket_callbacks(x) cast(x, rebrick_tlssocket_callbacks_t *);

/*
 * @brief creates a tls socket with SNI(server name indication) pattern
 *
 * @param socket socket pointer
 * @param sni pattern or name for finding client sni or setting client sni
 * @param dst_addr destination address and port, if port is zero then only listening socket opens
 * @param callback_data, callback data parameter for every callback
 * @param on_data_received data received callback
 * @param on_data_sended
 * @return int32_t
 */
int32_t rebrick_tlssocket_new(rebrick_tlssocket_t **socket, const char *sni_pattern_or_name, rebrick_tls_context_t *tls_context, rebrick_sockaddr_t addr,
                              int32_t backlog_or_isclient, const rebrick_tlssocket_callbacks_t *callbacks);

/**
 * @brief inits a socket, think init functions like contructors in OOP
 *
 * @param socket
 * @param tls_context
 * @param addr
 * @param callback_data
 * @param on_connection_accepted
 * @param on_connection_closed
 * @param on_data_received
 * @param on_data_sended
 * @param on_error_occured
 * @param backlog_or_isclient
 * @param create_client
 * @return int32_t
 */
int32_t rebrick_tlssocket_init(rebrick_tlssocket_t *socket, const char *sni_pattern_or_name, const rebrick_tls_context_t *tls_context, rebrick_sockaddr_t addr,
                               int32_t backlog_or_isclient, rebrick_tcpsocket_create_client_t create_client,
                               const rebrick_tlssocket_callbacks_t *callbacks);

int32_t rebrick_tlssocket_destroy(rebrick_tlssocket_t *socket);
int32_t rebrick_tlssocket_write(rebrick_tlssocket_t *socket, uint8_t *buffer, size_t len, rebrick_clean_func_t cleanfunc);

int32_t rebrick_tlssocket_change_context(rebrick_tlssocket_t *socket, const char *servername);
#endif