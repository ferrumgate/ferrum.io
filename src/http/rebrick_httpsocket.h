
#ifndef __REBRICK_HTTPSOCKET_H__
#define __REBRICK_HTTPSOCKET_H__

#include "rebrick_http.h"


typedef enum{
    http2,
    websocket,
    websocket2
}upgrade_socket_type_t;

struct rebrick_httpsocket;
/**
 * @brief after a http header parsed, executes this callback
 * @param socket, which socket
 * @param header received header
 * @param status, result of parsing, parsed successfully or error
 */
typedef void (*rebrick_on_http_header_received_callback_t)(struct rebrick_socket *socket,int32_t stream_id, void *callback_data, rebrick_http_header_t *header);

/**
 * @brief after header parsed finished, when body data starts to come,
 * this callback trigger,this is a synonym
 * @see rebrick_on_data_received_callback_t
 */
typedef void (*rebrick_on_http_body_received_callback_t)(struct rebrick_socket *socket,int32_t stream_id, void *callback_data, const struct sockaddr *addr, const uint8_t *buffer, ssize_t len);



typedef void (*rebrick_on_socket_upgrade_callback_t)(struct rebrick_socket *socket,void *callback_data,upgrade_socket_type_t type);

/**
 * @brief http socket structure
 * allways executes callback when new data arrives
 *
 */
public_ typedef struct rebrick_httpsocket
{
    base_ssl_socket();

    private_ rebrick_on_connection_accepted_callback_t override_override_on_connection_accepted;
    private_ rebrick_on_connection_closed_callback_t override_override_on_connection_closed;
    private_ rebrick_on_data_received_callback_t override_override_on_data_received;
    private_ rebrick_on_data_sended_callback_t  override_override_on_data_sended;
    private_ rebrick_on_error_occured_callback_t override_override_on_error_occured;
    private_ rebrick_on_http_header_received_callback_t on_http_header_received;
    private_ rebrick_on_http_body_received_callback_t on_http_body_received;
    private_ rebrick_tls_context_t *override_override_tls_context;
    private_ void *override_override_callback_data;


    public_ readonly_ rebrick_http_header_t *header;



    private_ rebrick_buffer_t *tmp_buffer;
    private_ int32_t is_header_parsed;
    public_ size_t header_len;
    public_ readonly_ size_t content_received_length;




    struct{
        struct phr_header headers[REBRICK_HTTP_MAX_HEADERS];
        const char *method, *path;
        int  minor_version;
        size_t method_len, path_len, num_headers;
        int32_t status;
        const char *status_msg;
        size_t status_msg_len;
        size_t pos;
    }parsing_params;



} rebrick_httpsocket_t;




#define cast_to_http_socket(x) cast(x,rebrick_httpsocket_t*);



int32_t rebrick_httpsocket_new(rebrick_httpsocket_t **socket,const char *sni_pattern_or_name, rebrick_tls_context_t *tls,rebrick_sockaddr_t addr, void *callback_data,
                                    rebrick_on_connection_accepted_callback_t on_connection_accepted,
                                    rebrick_on_connection_closed_callback_t on_connection_closed,
                                    rebrick_on_data_received_callback_t on_data_received,
                                    rebrick_on_data_sended_callback_t on_data_sended,
                                    rebrick_on_error_occured_callback_t on_error_occured, int32_t backlog_or_isclient,
                                    rebrick_on_http_header_received_callback_t on_http_header_received,
                                    rebrick_on_http_body_received_callback_t on_http_body_received);

int32_t rebrick_httpsocket_init(rebrick_httpsocket_t *socket, const char *sni_pattern_or_name, rebrick_tls_context_t *tls,rebrick_sockaddr_t addr, void *callback_data,
                                    rebrick_on_connection_accepted_callback_t on_connection_accepted,
                                    rebrick_on_connection_closed_callback_t on_connection_closed,
                                    rebrick_on_data_received_callback_t on_data_received,
                                    rebrick_on_data_sended_callback_t on_data_sended,
                                    rebrick_on_error_occured_callback_t on_error_occured, int32_t backlog_or_isclient,
                                    rebrick_on_http_header_received_callback_t after_http_request_received,
                                    rebrick_on_http_body_received_callback_t after_http_body_received,
                                    rebrick_tcpsocket_create_client_t create_client);

int32_t rebrick_httpsocket_destroy(rebrick_httpsocket_t *socket);
int32_t rebrick_httpsocket_send(rebrick_httpsocket_t *socket,int32_t stream_id, uint8_t *buffer, size_t len, rebrick_clean_func_t cleanfunc);
int32_t rebrick_httpsocket_reset(rebrick_httpsocket_t *socket);
int32_t rebrick_httpsocket_send_header(rebrick_httpsocket_t *socket,int32_t stream_id,rebrick_http_header_t *header);
int32_t rebrick_httpsocket_send_body(rebrick_httpsocket_t *socket,int32_t stream_id, uint8_t *buffer,size_t len,rebrick_clean_func_t cleanfunc);







#endif