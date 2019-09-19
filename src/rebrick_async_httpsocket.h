
#ifndef __REBRICK_ASYNC_HTTPSOCKET_H__
#define __REBRICK_ASYNC_HTTPSOCKET_H__

#include "rebrick_async_tlssocket.h"
#include "rebrick_buffers.h"
#include "./lib/picohttpparser.h"



#define REBRICK_HTTP_MAX_HEADER_LEN 8192
#define REBRICK_HTTP_MAX_HOSTNAME_LEN 1024
#define REBRICK_HTTP_MAX_URI_LEN 8192
#define REBRICK_HTTP_MAX_PATH_LEN 8192
#define REBRICK_HTTP_MAX_METHOD_LEN 512



public_ typedef struct rebrick_http_header{
    base_object();
    public_ char path[REBRICK_HTTP_MAX_PATH_LEN];
    public_ char method[REBRICK_HTTP_MAX_METHOD_LEN];
    public_ int8_t major_version;
    public_ int8_t minor_version;
    public_ int16_t status_code;
    public_ struct phr_header *headers;


}rebrick_http_header_t;

/* public_ typedef struct rebrick_http_body{
     base_object();
    public_ rebrick_buffers_t *body;


}rebrick_http_body_t; */


struct rebrick_async_httpsocket;
/**
 * @brief after a http header parsed, executes this callback
 * @param socket, which socket
 * @param header received header
 * @param status, result of parsing, parsed successfully or error
 */
typedef int32_t (*rebrick_on_http_request_received_callback_t)(struct rebrick_async_httpsocket *socket, rebrick_http_header_t *header,int32_t status);
/**
 * @brief after header parsed finished, when body data starts to come,
 * this callback trigger,this is a synonym
 * @see rebrick_on_data_received_callback_t
 */
typedef rebrick_on_data_received_callback_t rebrick_on_http_body_received_callback_t;

/**
 * @brief http socket structure
 * allways executes callback when new data arrives
 *
 */
public_ typedef struct rebrick_async_httpsocket
{
    base_ssl_socket();

    private_ rebrick_on_connection_accepted_callback_t override_override_on_connection_accepted;
    private_ rebrick_on_connection_closed_callback_t override_override_on_connection_closed;
    private_ rebrick_on_data_received_callback_t override_override_on_data_received;
    private_ rebrick_on_data_sended_callback_t  override_override_on_data_sended;
    private_ rebrick_on_error_occured_callback_t override_override_on_error_occured;
    private_ rebrick_on_http_request_received_callback_t after_http_header_received;
    private_ rebrick_on_http_body_received_callback_t after_http_body_received;
    private_ rebrick_tls_context_t *override_override_tls_context;
    private_ void *override_override_callback_data;


    private_ rebrick_http_header_t *header;

    private_ rebrick_buffers_t *tmp_buffer;
    private_ int32_t is_header_parsed;

    struct{
       size_t buflen, prevbuflen , method_len, path_len, num_headers;
    }parsing_params;






} rebrick_async_httpsocket_t;




#define cast_to_http_socket(x) cast(x,rebrick_async_httpsocket_t*);



int32_t rebrick_async_httpsocket_new(rebrick_async_httpsocket_t **socket,rebrick_tls_context_t *tls,rebrick_sockaddr_t addr, void *callback_data,
                                    rebrick_on_connection_accepted_callback_t on_connection_accepted,
                                    rebrick_on_connection_closed_callback_t on_connection_closed,
                                    rebrick_on_data_received_callback_t on_data_received,
                                    rebrick_on_data_sended_callback_t on_data_sended,
                                    rebrick_on_error_occured_callback_t on_error_occured, int32_t backlog_or_isclient,
                                    rebrick_on_http_request_received_callback_t after_http_request_received,
                                    rebrick_on_http_body_received_callback_t after_http_body_received);

int32_t rebrick_async_httpsocket_init(rebrick_async_httpsocket_t *socket,rebrick_tls_context_t *tls,rebrick_sockaddr_t addr, void *callback_data,
                                    rebrick_on_connection_accepted_callback_t on_connection_accepted,
                                    rebrick_on_connection_closed_callback_t on_connection_closed,
                                    rebrick_on_data_received_callback_t on_data_received,
                                    rebrick_on_data_sended_callback_t on_data_sended,
                                    rebrick_on_error_occured_callback_t on_error_occured, int32_t backlog_or_isclient,
                                    rebrick_on_http_request_received_callback_t after_http_request_received,
                                    rebrick_on_http_body_received_callback_t after_http_body_received);
int32_t rebrick_async_httpsocket_destroy(rebrick_async_httpsocket_t *socket);
int32_t rebrick_async_httpsocket_send(rebrick_async_httpsocket_t *socket, char *buffer, size_t len, rebrick_clean_func_t cleanfunc);






#endif