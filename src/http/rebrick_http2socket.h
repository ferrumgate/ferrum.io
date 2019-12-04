#ifndef __REBRICK_HTTP2SOCKET_H__
#define __REBRICK_HTTP2SOCKET_H__

#include <nghttp2/nghttp2.h>
#include <nghttp2/nghttp2ver.h>
#include "rebrick_http.h"
#include "rebrick_httpsocket.h"

#define REBRICK_HTTP_FLAGS_NONE 0x0
#define REBRICK_HTTP_FLAGS_EOF 0x1
#define REBRICK_HTTP_FLAGS_ENDSTREAM 0x2






typedef nghttp2_settings_entry rebrick_http2_settings_entry;

public_ typedef struct rebrick_http2_socket_settings
{
    rebrick_http2_settings_entry entries[64];
    size_t settings_count;
} rebrick_http2_socket_settings_t;



public_ typedef struct rebrick_http2_stream
{
    base_object();
    public_ readonly_ int32_t stream_id;
    public_ readonly_ int32_t parent_stream_id;
    public_ readonly_ rebrick_buffer_t *buffer;
    public_ readonly_ int32_t flags;
    public_ readonly_ int32_t is_submitted;
    public_ readonly_ rebrick_http_header_t *received_header;
    public_ readonly_ rebrick_http_header_t *send_header;
    //make this hashtable
    private_ UT_hash_handle hh;
} rebrick_http2_stream_t;


typedef void (*rebrick_on_stream_closed_callback_t)(struct rebrick_socket *socket,int32_t stream_id, void *callback_data);
typedef void (*rebrick_on_settings_received_callback_t)(struct rebrick_socket *socket,void *callback_data,rebrick_http2_socket_settings_t *settings);
typedef void (*rebrick_on_ping_received_callback_t)(struct rebrick_socket *socket,void *callback_data,const uint8_t opaqua_data[8]);
typedef void (*rebrick_on_push_received_callback_t)(struct rebrick_socket *socket,void *callback_data,int32_t stream_id,int32_t push_stream_id,rebrick_http_header_t *header);
typedef void (*rebrick_on_goaway_received_callback_t)(struct rebrick_socket *socket,void *callback_data,int32_t errorcode,int32_t laststream_id,uint8_t *opaque_data,size_t opaque_data_len);
typedef void (*rebrick_on_window_update_callback_t)(struct rebrick_socket *socket,void *callback_data,int32_t stream, int32_t increment);

public_ typedef struct rebrick_http2socket
{

    base_ssl_socket();

    private_ rebrick_on_connection_accepted_callback_t override_override_on_connection_accepted;
    private_ rebrick_on_connection_closed_callback_t override_override_on_connection_closed;
    private_ rebrick_on_data_received_callback_t override_override_on_data_received;
    private_ rebrick_on_data_sended_callback_t override_override_on_data_sended;
    private_ rebrick_on_error_occured_callback_t override_override_on_error_occured;
    private_ rebrick_on_http_header_received_callback_t on_http_header_received;
    private_ rebrick_on_http_body_received_callback_t on_http_body_received;
    private_ rebrick_on_socket_needs_upgrade_callback_t on_socket_needs_upgrade;
    private_ rebrick_on_stream_closed_callback_t on_stream_closed;
    private_ rebrick_on_settings_received_callback_t on_settings_received;
    private_ rebrick_on_ping_received_callback_t on_ping_received;
    private_ rebrick_on_push_received_callback_t on_push_received;
    private_ rebrick_on_goaway_received_callback_t on_goaway_received;
    private_ rebrick_on_window_update_callback_t on_window_update_received;
    private_ void *override_override_callback_data;
    protected_ int32_t is_goaway_sended;
    protected_ int32_t is_goaway_received;
    protected_ int32_t last_received_stream_id;


    private_ struct
    {
        nghttp2_session *session;
        nghttp2_session_callbacks *session_callback;
    } parsing_params;

    private_ rebrick_http2_socket_settings_t settings;
    private_ rebrick_http2_socket_settings_t received_settings;



    private_ rebrick_http2_stream_t *streams;

} rebrick_http2socket_t;


#define cast_to_http2socket(s) cast(s, rebrick_http2socket_t *)

#define base_http2socket_callbacks() \
        base_tlssocket_callbacks();\
        rebrick_on_http_header_received_callback_t on_http_header_received;\
        rebrick_on_http_body_received_callback_t on_http_body_received;\
        rebrick_on_socket_needs_upgrade_callback_t on_socket_needs_upgrade;\
        rebrick_on_stream_closed_callback_t on_stream_closed;\
        rebrick_on_settings_received_callback_t on_settings_received;\
        rebrick_on_ping_received_callback_t on_ping_received;\
        rebrick_on_push_received_callback_t on_push_received;\
        rebrick_on_goaway_received_callback_t on_goaway_received;\
        rebrick_on_window_update_callback_t on_window_update_received;\

typedef struct rebrick_http2socket_callbacks{
    base_http2socket_callbacks();
}rebrick_http2socket_callbacks_t;

#define cast_to_http2socket_callbacks(x) cast(x,rebrick_http2socket_callbacks_t*)

int32_t rebrick_http2socket_new(rebrick_http2socket_t **socket, const char *sni_pattern_or_name, rebrick_tls_context_t *tls, rebrick_sockaddr_t addr,
                                int32_t backlog_or_isclient,
                                const rebrick_http2_socket_settings_t *settings,const rebrick_http2socket_callbacks_t *callbacks);

int32_t rebrick_http2socket_init(rebrick_http2socket_t *socket, const char *sni_pattern_or_name, rebrick_tls_context_t *tls, rebrick_sockaddr_t addr,
                                 int32_t backlog_or_isclient,rebrick_tcpsocket_create_client_t create_client,
                                 const rebrick_http2_socket_settings_t *settings,const rebrick_http2socket_callbacks_t *callbacks);

int32_t rebrick_http2socket_destroy(rebrick_http2socket_t *socket);
protected_ int32_t rebrick_http2socket_send(rebrick_http2socket_t *socket, uint8_t *buffer, size_t len, rebrick_clean_func_t cleanfunc);
/**
 * @brief
 *
 * @param socket
 * @param stream_id if *stream_id=-1 then new stream_id will return
 * @param flags @see NGHTTP2_FLAGS_NONE or @see NGHTTP2_FLAGS_END_STREAM
 * @param header
 * @return int32_t
 */
int32_t rebrick_http2socket_send_header(rebrick_http2socket_t *socket, int32_t *stream_id, int64_t flags,rebrick_http_header_t *header);

/**
 * @brief send body data after header
 *
 * @param socket
 * @param stream_id
 * @param flags 0xABCD  A and B not used 8 bits, only C and D are using, C is @see NGHTTP2_FLAG_END_STREAM or NGHTTP2_FLAG_NONE @see D is  NGHTTP2_DATA_FLAG_NONE or NGHTTP2_DATA_FLAG_EOF
 * @param buffer
 * @param len
 * @param cleanfunc
 * @return int32_t
 */
int32_t rebrick_http2socket_send_body(rebrick_http2socket_t *socket, int32_t stream_id, int64_t flags, uint8_t *buffer, size_t len, rebrick_clean_func_t cleanfunc);

int32_t rebrick_http2socket_get_stream(rebrick_http2socket_t *socket,int32_t stream_id,rebrick_http2_stream_t **stream);

int32_t rebrick_http2socket_send_goaway(rebrick_http2socket_t *socket,uint8_t *opaque_data,size_t opaque_data_len);

int32_t rebrick_http2socket_send_ping(rebrick_http2socket_t *socket,int64_t flags, uint8_t opaque_data[8]);

int32_t rebrick_http2socket_send_window_update(rebrick_http2socket_t *socket,int32_t stream_id,int32_t increment);
int32_t rebrick_http2socket_send_push(rebrick_http2socket_t *socket,int32_t *pushstream_id,int32_t stream_id,rebrick_http_header_t *header);
int32_t rebrick_http2socket_send_rststream(rebrick_http2socket_t *socket,int32_t stream_id,uint32_t errorcode);


#endif