
#ifndef __REBRICK_ASYNC_HTTPSOCKET_H__
#define __REBRICK_ASYNC_HTTPSOCKET_H__

#include "rebrick_async_tlssocket.h"
#include "rebrick_buffer.h"
#include "./lib/picohttpparser.h"
#include "./lib/uthash.h"



#define REBRICK_HTTP_MAX_HEADER_LEN 8192
#define REBRICK_HTTP_MAX_HOSTNAME_LEN 1024
#define REBRICK_HTTP_MAX_URI_LEN 8192
#define REBRICK_HTTP_MAX_PATH_LEN 8192
#define REBRICK_HTTP_MAX_METHOD_LEN 16
#define REBRICK_HTTP_MAX_HEADERS 100



public_ typedef struct rebrick_http_key_value{
    public_ readonly_ char *key;
    public_ size_t keylen;
    public_ readonly_ char *value;
    public_ size_t valuelen;
    UT_hash_handle hh;
}rebrick_http_key_value_t;

int32_t rebrick_http_key_value_new(rebrick_http_key_value_t **keyvalue,const char *key,const char *value);
int32_t rebrick_http_key_value_new2(rebrick_http_key_value_t **keyvalue,const void *key,size_t keylen,const void *value,size_t valuelen);
int32_t rebrick_http_key_value_destroy(rebrick_http_key_value_t *keyvalue);

public_ typedef struct rebrick_http_header{
    base_object();
    public_ char path[REBRICK_HTTP_MAX_PATH_LEN];
    public_ char method[REBRICK_HTTP_MAX_METHOD_LEN];
    public_ int8_t major_version;
    public_ int8_t minor_version;
    public_ int16_t status_code;
    public_ rebrick_http_key_value_t *headers;



}rebrick_http_header_t;

int32_t rebrick_http_header_new(rebrick_http_header_t **header,const char *path,const char *method,int majorversion);
int32_t rebrick_http_header_new2(rebrick_http_header_t **header,const char *path,const char *method,int8_t major,int8_t minor);
int32_t rebrick_http_header_add_header(rebrick_http_header_t *header,const char *key,const char*value);
int32_t rebrick_http_header_contains_key(rebrick_http_header_t *header,const char *key);
int32_t rebrick_http_header_remove_key(rebrick_http_header_t *header,const char *key);
int32_t rebrick_http_header_destroy(rebrick_http_header_t *header);




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
typedef int32_t (*rebrick_on_http_header_received_callback_t)(struct rebrick_async_socket *socket, void *callback_data, rebrick_http_header_t *header,int32_t status);
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
    private_ rebrick_on_http_header_received_callback_t on_http_header_received;
    private_ rebrick_on_http_body_received_callback_t on_http_body_received;
    private_ rebrick_tls_context_t *override_override_tls_context;
    private_ void *override_override_callback_data;


    public_ readonly_ rebrick_http_header_t *header;

    private_ rebrick_buffer_t *tmp_buffer;
    private_ int32_t is_header_parsed;
    public_ size_t header_len;
    public_ size_t body_must_len;
    public_ size_t body_received_len;



    struct{
        struct phr_header headers[REBRICK_HTTP_MAX_HEADERS];
        char *method, *path;
        int  minor_version;
        size_t method_len, path_len, num_headers;
    }parsing_params;



} rebrick_async_httpsocket_t;




#define cast_to_http_socket(x) cast(x,rebrick_async_httpsocket_t*);



int32_t rebrick_async_httpsocket_new(rebrick_async_httpsocket_t **socket,rebrick_tls_context_t *tls,rebrick_sockaddr_t addr, void *callback_data,
                                    rebrick_on_connection_accepted_callback_t on_connection_accepted,
                                    rebrick_on_connection_closed_callback_t on_connection_closed,
                                    rebrick_on_data_received_callback_t on_data_received,
                                    rebrick_on_data_sended_callback_t on_data_sended,
                                    rebrick_on_error_occured_callback_t on_error_occured, int32_t backlog_or_isclient,
                                    rebrick_on_http_header_received_callback_t on_http_header_received,
                                    rebrick_on_http_body_received_callback_t on_http_body_received);

int32_t rebrick_async_httpsocket_init(rebrick_async_httpsocket_t *socket,rebrick_tls_context_t *tls,rebrick_sockaddr_t addr, void *callback_data,
                                    rebrick_on_connection_accepted_callback_t on_connection_accepted,
                                    rebrick_on_connection_closed_callback_t on_connection_closed,
                                    rebrick_on_data_received_callback_t on_data_received,
                                    rebrick_on_data_sended_callback_t on_data_sended,
                                    rebrick_on_error_occured_callback_t on_error_occured, int32_t backlog_or_isclient,
                                    rebrick_on_http_header_received_callback_t after_http_request_received,
                                    rebrick_on_http_body_received_callback_t after_http_body_received,
                                    rebrick_async_tcpsocket_create_client_t create_client);
int32_t rebrick_async_httpsocket_destroy(rebrick_async_httpsocket_t *socket);
int32_t rebrick_async_httpsocket_send(rebrick_async_httpsocket_t *socket, char *buffer, size_t len, rebrick_clean_func_t cleanfunc);







#endif