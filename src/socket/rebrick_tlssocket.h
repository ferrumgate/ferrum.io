#ifndef __REBRICK_TLSSOCKET_H__
#define __REBRICK_TLSSOCKET_H__

#include "../common/rebrick_tls.h"
#include "./rebrick_tcpsocket.h"
#include "../common/rebrick_buffers.h"


/**
 * @brief openssl is an interesting library, that sometimes you need pending data
 *
 */
protected_ typedef struct pending_data{
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
    struct pending_data *prev,*next;
}pending_data_t;



#define base_ssl_socket()   \
        base_tcp_socket(); \
        private_ const rebrick_tls_context_t *tls_context; \
        private_ rebrick_tls_ssl_t *tls; \
        private_ rebrick_on_connection_accepted_callback_t override_on_connection_accepted; \
        private_ rebrick_on_connection_closed_callback_t override_on_connection_closed; \
        private_ rebrick_on_data_received_callback_t override_on_data_received; \
        private_ rebrick_on_data_sended_callback_t   override_on_data_sended; \
        private_ rebrick_on_error_occured_callback_t override_on_error_occured;\
        private_ void *override_callback_data; \
        private_ pending_data_t *pending_write_list; \
        private_ int32_t called_override_after_connection_accepted; \
        public_ readonly_ int32_t is_server;\
        private_ int32_t sslhandshake_initted;  \
        public_ readonly_ char sni_pattern_or_name[REBRICK_TLS_SNI_MAX_LEN];\
        public_ readonly_ char sni[REBRICK_TLS_SNI_MAX_LEN];



public_ typedef struct rebrick_tlssocket
{
    base_ssl_socket()


} rebrick_tlssocket_t;



#define cast_to_tls_socket(x) cast(x, rebrick_tlssocket_t *)

/**
 * @brief
 *
 * @param socket socket pointer
 * @param tls_context  tls context
 * @param bind_addr bind address and port
 * @param dst_addr destination address and port, if port is zero then only listening socket opens
 * @param callback_data, callback data parameter for every callback
 * @param on_data_received data received callback
 * @param on_data_sended
 * @return int32_t
 */
int32_t rebrick_tlssocket_new(rebrick_tlssocket_t **socket, const rebrick_tls_context_t *tls_context, rebrick_sockaddr_t addr, void *callback_data,
                                    rebrick_on_connection_accepted_callback_t on_connection_accepted,
                                    rebrick_on_connection_closed_callback_t on_connection_closed,
                                    rebrick_on_data_received_callback_t on_data_received,
                                    rebrick_on_data_sended_callback_t on_data_sended,
                                    rebrick_on_error_occured_callback_t on_error_occured, int32_t backlog_or_isclient);

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
int32_t rebrick_tlssocket_new2(rebrick_tlssocket_t **socket, const char *sni_pattern_or_name, rebrick_tls_context_t *tls_context, rebrick_sockaddr_t addr, void *callback_data,
                                    rebrick_on_connection_accepted_callback_t on_connection_accepted,
                                    rebrick_on_connection_closed_callback_t on_connection_closed,
                                    rebrick_on_data_received_callback_t on_data_received,
                                    rebrick_on_data_sended_callback_t on_data_sended,
                                    rebrick_on_error_occured_callback_t on_error_occured, int32_t backlog_or_isclient);

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
int32_t rebrick_tlssocket_init(rebrick_tlssocket_t *socket, const rebrick_tls_context_t *tls_context, rebrick_sockaddr_t addr, void *callback_data,
                                    rebrick_on_connection_accepted_callback_t on_connection_accepted,
                                    rebrick_on_connection_closed_callback_t on_connection_closed,
                                    rebrick_on_data_received_callback_t on_data_received,
                                    rebrick_on_data_sended_callback_t on_data_sended,
                                    rebrick_on_error_occured_callback_t on_error_occured, int32_t backlog_or_isclient,rebrick_tcpsocket_create_client_t create_client);

int32_t rebrick_tlssocket_destroy(rebrick_tlssocket_t *socket);
int32_t rebrick_tlssocket_send(rebrick_tlssocket_t *socket, char *buffer, size_t len, rebrick_clean_func_t cleanfunc);

int32_t rebrick_tlssocket_change_context(rebrick_tlssocket_t *socket,const char *servername);
#endif