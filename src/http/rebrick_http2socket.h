#ifndef __REBRICK_HTTP2SOCKET_H__
#define __REBRICK_HTTP2SOCKET_H__


#include <nghttp2/nghttp2.h>
#include <nghttp2/nghttp2ver.h>
#include "rebrick_http.h"
#include "rebrick_httpsocket.h"




typedef nghttp2_settings_entry rebrick_http2_settings_entry;

public_ typedef struct rebrick_http2_socket_settings{
    rebrick_http2_settings_entry entries[64];
    size_t settings_count;
}rebrick_http2_socket_settings_t;

private_ typedef struct rebrick_http2stream{
    int32_t stream_id;
    rebrick_buffer_t *buffer;
    //make this hashtable
    UT_hash_handle hh;
}rebrick_http2stream_t;

public_ typedef struct rebrick_http2socket{

    base_ssl_socket();

    private_ rebrick_on_connection_accepted_callback_t override_override_on_connection_accepted;
    private_ rebrick_on_connection_closed_callback_t override_override_on_connection_closed;
    private_ rebrick_on_data_received_callback_t override_override_on_data_received;
    private_ rebrick_on_data_sended_callback_t  override_override_on_data_sended;
    private_ rebrick_on_error_occured_callback_t override_override_on_error_occured;
    private_ void *override_override_callback_data;

    public_ readonly_ rebrick_http_header_t *header;

    private_ struct{
        nghttp2_session *session;
        nghttp2_session_callbacks *session_callback;
    }parsing_params;

    private_ rebrick_http2_socket_settings_t settings;

    private_ rebrick_http2stream_t *streams;




}rebrick_http2socket_t;

#define cast_to_http2_socket(socket)  cast(socket,rebrick_http2socket_t*)


int32_t rebrick_http2socket_new(rebrick_http2socket_t **socket,const char *sni_pattern_or_name, rebrick_tls_context_t *tls,rebrick_sockaddr_t addr, void *callback_data,
                                    const rebrick_http2_socket_settings_t *settings,
                                    rebrick_on_connection_accepted_callback_t on_connection_accepted,
                                    rebrick_on_connection_closed_callback_t on_connection_closed,
                                    rebrick_on_data_received_callback_t on_data_received,
                                    rebrick_on_data_sended_callback_t on_data_sended,
                                    rebrick_on_error_occured_callback_t on_error_occured, int32_t backlog_or_isclient);

int32_t rebrick_http2socket_init(rebrick_http2socket_t *socket, const char *sni_pattern_or_name, rebrick_tls_context_t *tls,rebrick_sockaddr_t addr, void *callback_data,
                                    const rebrick_http2_socket_settings_t *settings,
                                    rebrick_on_connection_accepted_callback_t on_connection_accepted,
                                    rebrick_on_connection_closed_callback_t on_connection_closed,
                                    rebrick_on_data_received_callback_t on_data_received,
                                    rebrick_on_data_sended_callback_t on_data_sended,
                                    rebrick_on_error_occured_callback_t on_error_occured, int32_t backlog_or_isclient,
                                    rebrick_tcpsocket_create_client_t create_client);

int32_t rebrick_http2socket_destroy(rebrick_http2socket_t *socket);
int32_t rebrick_http2socket_send(rebrick_http2socket_t *socket, uint8_t *buffer, size_t len, rebrick_clean_func_t cleanfunc);
/**
 * @brief
 *
 * @param socket
 * @param stream_id if *stream_id=-1 then new stream_id will return
 * @param flags @see NGHTTP2_FLAGS_NONE or @see NGHTTP2_FLAGS_END_STREAM
 * @param header
 * @return int32_t
 */
int32_t rebrick_http2socket_send_header(rebrick_http2socket_t *socket,int32_t *stream_id,int32_t flags, rebrick_http_header_t *header);
int32_t rebrick_http2socket_send_body(rebrick_http2socket_t *socket,int32_t stream_id,int32_t flags, uint8_t *buffer,size_t len,rebrick_clean_func_t cleanfunc);




#endif