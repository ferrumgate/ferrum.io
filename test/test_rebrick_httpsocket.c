#include "./http/rebrick_httpsocket.h"
#include "cmocka.h"
#include <unistd.h>


#define loop(var,a,x) \
    var=a; \
 while (var-- && (x)){ usleep(100); uv_run(uv_default_loop(), UV_RUN_NOWAIT);}

static rebrick_tls_context_t *context_verify_none = NULL;
static int setup(void**state){
    unused(state);
    rebrick_tls_init();
    rebrick_tls_context_new(&context_verify_none, "client", SSL_VERIFY_NONE, SSL_SESS_CACHE_BOTH, SSL_OP_ALL,0, NULL, NULL);
    fprintf(stdout,"****  %s ****\n",__FILE__);
    return 0;
}

static int teardown(void **state){
    unused(state);
    int32_t loop_counter;
    rebrick_tls_context_destroy(context_verify_none);
    context_verify_none = NULL;
    rebrick_tls_cleanup();
    loop(loop_counter,100,TRUE);
    uv_loop_close(uv_default_loop());
    return 0;
}


static void on_error_occured_callback(rebrick_socket_t *socket,void *callback,int error){
    unused(socket);
    unused(callback);
    unused(error);
    rebrick_tlssocket_destroy(cast(socket, rebrick_tlssocket_t *));

}

static int32_t is_connected = FALSE;

static void on_connection_accepted_callback(rebrick_socket_t *socket, void *callback_data, const struct sockaddr *addr, void *client_handle)
{
    is_connected = TRUE;

    unused(callback_data);
    unused(addr);
    unused(client_handle);
    unused(socket);

}
static int32_t is_connection_closed = 0;
static void on_connection_closed_callback(rebrick_socket_t *socket, void *callback_data)
{
    unused(callback_data);
    unused(socket);
    is_connection_closed = 1;


}
static int32_t is_datareaded = FALSE;
static int32_t totalreaded_len = 0;
static char readedbuffer[131072] = {0};
static void on_data_read_callback(rebrick_socket_t *socket, void *callback_data, const struct sockaddr *addr, const uint8_t *buffer, ssize_t len)
{
    unused(addr);
    unused(socket);
    unused(addr);
    unused(buffer);
    unused(len);
    unused(callback_data);

        is_datareaded = TRUE;
        fill_zero(readedbuffer, sizeof(readedbuffer));

        memcpy(readedbuffer, buffer, len);

        totalreaded_len += len;


}
static int32_t sended=FALSE;
static void on_data_send(rebrick_socket_t *socket,void *callback,void *source){
    unused(socket);
    unused(callback);
    unused(source);

sended=TRUE;


}
static int32_t header_received=FALSE;
static void on_http_header_received(rebrick_socket_t *socket,int32_t stream_id,void *callback_data,rebrick_http_header_t *header){
    unused(socket);
    unused(callback_data);
    unused(header);
    //stream id is useless, at least this is not http2
    unused(stream_id);

    header_received=TRUE;

}


static int32_t is_bodyreaded = FALSE;
static int32_t totalreadedbody_len = 0;
static char readedbufferbody[131072] = {0};
static void on_body_read_callback(rebrick_socket_t *socket,int32_t stream_id, void *callback_data, const struct sockaddr *addr, const uint8_t *buffer, ssize_t len)
{
    unused(addr);
    unused(socket);
    unused(addr);
    unused(buffer);
    unused(len);
    //this is http, stream id is allways zero
    unused(stream_id);
    unused(callback_data);

        is_bodyreaded = TRUE;
        fill_zero(readedbufferbody, sizeof(readedbufferbody));

        memcpy(readedbufferbody, buffer, len);

        totalreadedbody_len += len;


}

void deletesendata(void *ptr){
    if(ptr){
        rebrick_buffer_t *buffer=cast(ptr,rebrick_buffer_t *);
        rebrick_buffer_destroy(buffer);
    }
}






static void http_socket_as_client_create_get(void **start){
    unused(start);
    int32_t result;
    int32_t counter;

    rebrick_sockaddr_t destination;

    rebrick_util_ip_port_to_addr("127.0.0.1", "9090", &destination);

    rebrick_httpsocket_t *socket;
    is_connected=FALSE;

    result = rebrick_httpsocket_new(&socket,NULL, NULL, destination, NULL,
                on_connection_accepted_callback,
                on_connection_closed_callback,
                on_data_read_callback, on_data_send,on_error_occured_callback,0,on_http_header_received,on_body_read_callback,NULL);
    assert_int_equal(result, 0);

    loop(counter,1000,!is_connected);
    assert_int_equal(is_connected,TRUE);

    rebrick_http_header_t *header;
    result=rebrick_http_header_new(&header,"http","localhost", "GET", "/api/get",1,1);
    assert_int_equal(result,REBRICK_SUCCESS);
    rebrick_buffer_t *buffer;
    result=rebrick_http_header_to_http_buffer(header,&buffer);
    assert_int_equal(result,REBRICK_SUCCESS);
    assert_non_null(buffer);

    sended=FALSE;
    header_received=FALSE;
    is_bodyreaded=FALSE;
    rebrick_clean_func_t cleanfunc;
    cleanfunc.func=deletesendata;
    cleanfunc.ptr=buffer;
    //send data
    result=rebrick_httpsocket_send(socket,buffer->buf,buffer->len,cleanfunc);
    assert_int_equal(result,REBRICK_SUCCESS);
    loop(counter,1000,(!sended));
    assert_int_equal(sended,TRUE);
    loop(counter,100,!header_received);
    assert_int_equal(header_received,TRUE);
    loop(counter,100,!is_bodyreaded);
    assert_int_equal(is_bodyreaded,TRUE);
    assert_non_null(socket->header);
    assert_int_equal(socket->header->major_version,1);
    assert_int_equal(socket->header->minor_version,1);
    assert_int_equal(socket->header->is_request,FALSE);
    assert_string_equal(socket->header->path,"");
    assert_string_equal(socket->header->method,"");
    assert_string_equal(socket->header->status_code_str,"OK");
    assert_int_equal(socket->header->status_code,200);
    const char *value;
    rebrick_http_header_get_header(socket->header,"X-Powered-By",&value);
    assert_string_equal(value,"Express");
    rebrick_http_header_get_header(socket->header,"Content-Type",&value);
    assert_string_equal(value,"text/html; charset=utf-8");
    rebrick_http_header_get_header(socket->header,"Content-Length",&value);
    assert_string_equal(value,"25");
     /*rebrick_http_header_get_header(socket->header,"ETag",&value);
    assert_string_equal(value,"W/\"19-EE0dTSKO8nU0PWVui0tLx8f6m9I\"");
     rebrick_http_header_get_header(socket->header,"Date",&value);
    assert_string_equal(value,"Sun, 22 Sep 2019 20:14:00 GMT");*/
     rebrick_http_header_get_header(socket->header,"Connection",&value);
    assert_string_equal(value,"keep-alive");


    assert_string_equal(readedbufferbody,"get captured successfully");




    rebrick_http_header_destroy(header);

    assert_int_equal(socket->content_received_length,25);
    rebrick_httpsocket_reset(socket);
    assert_int_equal(socket->content_received_length,0);
    assert_null(socket->header);
    assert_int_equal(socket->header_len,0);
    assert_int_equal(socket->is_header_parsed,0);
    assert_null(socket->tmp_buffer);

    rebrick_httpsocket_destroy(socket);
    loop(counter,100,TRUE);
}



static void http_socket_as_client_create_post(void **start){
    unused(start);
    int32_t result;
    int32_t counter=0;
    rebrick_sockaddr_t destination;

    rebrick_util_ip_port_to_addr("127.0.0.1", "9090", &destination);

    rebrick_httpsocket_t *socket;
    is_connected=FALSE;

    result = rebrick_httpsocket_new(&socket,NULL, NULL, destination, NULL,
                on_connection_accepted_callback,
                on_connection_closed_callback,
                on_data_read_callback, on_data_send,on_error_occured_callback,0,on_http_header_received,on_body_read_callback,NULL);
    assert_int_equal(result, REBRICK_SUCCESS);

    loop(counter,1000,!is_connected);
    assert_int_equal(is_connected,TRUE);

    char temp[1024];
     //body buffer
     const char *body="{\"hello\":\"world\"}";
    rebrick_buffer_t *bodybuffer;
    result=rebrick_buffer_new(&bodybuffer,cast_to_uint8ptr(body),strlen(body),64);
    assert_int_equal(result,REBRICK_SUCCESS);


    rebrick_http_header_t *header;
    result=rebrick_http_header_new(&header,"http","localhost", "POST", "/api/post",1,1);
    assert_int_equal(result,REBRICK_SUCCESS);
    rebrick_http_header_add_header(header,"content-type","application/json");
    sprintf(temp,"%ld",bodybuffer->len);
    rebrick_http_header_add_header(header,"content-length",temp);
    //header buffer
    rebrick_buffer_t *buffer;
    result=rebrick_http_header_to_http_buffer(header,&buffer);
    assert_int_equal(result,REBRICK_SUCCESS);
    assert_non_null(buffer);


    sended=FALSE;
    header_received=FALSE;
    is_bodyreaded=FALSE;
    rebrick_clean_func_t cleanfunc;
    cleanfunc.func=deletesendata;
    cleanfunc.ptr=buffer;
    result=rebrick_httpsocket_send(socket,buffer->buf,buffer->len,cleanfunc);
    assert_int_equal(result,REBRICK_SUCCESS);
    loop(counter,1000,(!sended));
    assert_int_equal(sended,TRUE);

    sended=FALSE;
    rebrick_clean_func_t cleanfunc2;
    cleanfunc2.func=deletesendata;
    cleanfunc2.ptr=bodybuffer;
    result=rebrick_httpsocket_send(socket,bodybuffer->buf,bodybuffer->len,cleanfunc2);
    loop(counter,1000,(!sended));
    assert_int_equal(sended,TRUE);



    loop(counter,100,!header_received);
    assert_int_equal(header_received,TRUE);
    loop(counter,100,!is_bodyreaded);
    assert_int_equal(is_bodyreaded,TRUE);
    assert_non_null(socket->header);
    assert_int_equal(socket->header->major_version,1);
    assert_int_equal(socket->header->minor_version,1);
    assert_int_equal(socket->header->is_request,FALSE);
    assert_string_equal(socket->header->path,"");
    assert_string_equal(socket->header->method,"");
    assert_string_equal(socket->header->status_code_str,"OK");
    assert_int_equal(socket->header->status_code,200);
    const char *value;
    rebrick_http_header_get_header(socket->header,"X-Powered-By",&value);
    assert_string_equal(value,"Express");
    rebrick_http_header_get_header(socket->header,"Content-Type",&value);
    assert_string_equal(value,"application/json; charset=utf-8");
    rebrick_http_header_get_header(socket->header,"Content-Length",&value);

    assert_int_equal(atoi(value),strlen(body));

     rebrick_http_header_get_header(socket->header,"Connection",&value);
    assert_string_equal(value,"keep-alive");


    assert_string_equal(readedbufferbody,body);




    rebrick_http_header_destroy(header);

    assert_int_equal(socket->content_received_length,strlen(body));
    rebrick_httpsocket_reset(socket);
    assert_int_equal(socket->content_received_length,0);
    assert_null(socket->header);
    assert_int_equal(socket->header_len,0);
    assert_int_equal(socket->is_header_parsed,0);
    assert_null(socket->tmp_buffer);

    rebrick_httpsocket_destroy(socket);
    loop(counter,100,TRUE);
}



static void http_socket_as_client_create_with_tls_post(void **start){
    unused(start);
    int32_t result;
    int32_t counter=0;
    rebrick_sockaddr_t destination;

    rebrick_util_ip_port_to_addr("127.0.0.1", "3000", &destination);

    rebrick_httpsocket_t *socket;
    is_connected=FALSE;

    result = rebrick_httpsocket_new(&socket,NULL, NULL, destination, NULL,
                on_connection_accepted_callback,
                on_connection_closed_callback,
                on_data_read_callback, on_data_send,on_error_occured_callback,0,on_http_header_received,on_body_read_callback,NULL);
    assert_int_equal(result, REBRICK_SUCCESS);

    loop(counter,1000,!is_connected);
    assert_int_equal(is_connected,TRUE);

    char temp[1024];
     //body buffer
     const char *body="{\"hello\":\"world\"}";
    rebrick_buffer_t *bodybuffer;
    result=rebrick_buffer_new(&bodybuffer,cast_to_uint8ptr(body),strlen(body),64);
    assert_int_equal(result,REBRICK_SUCCESS);


    rebrick_http_header_t *header;
    result=rebrick_http_header_new(&header,"https","localhost","POST", "/api/post",1,1);
    assert_int_equal(result,REBRICK_SUCCESS);
    rebrick_http_header_add_header(header,"content-type","application/json");
    sprintf(temp,"%ld",bodybuffer->len);
    rebrick_http_header_add_header(header,"content-length",temp);
    //header buffer
    rebrick_buffer_t *buffer;
    result=rebrick_http_header_to_http_buffer(header,&buffer);
    assert_int_equal(result,REBRICK_SUCCESS);
    assert_non_null(buffer);


    sended=FALSE;
    header_received=FALSE;
    is_bodyreaded=FALSE;
    rebrick_clean_func_t cleanfunc;
    cleanfunc.func=deletesendata;
    cleanfunc.ptr=buffer;
    result=rebrick_httpsocket_send(socket,buffer->buf,buffer->len,cleanfunc);
    assert_int_equal(result,REBRICK_SUCCESS);
    loop(counter,1000,(!sended));
    assert_int_equal(sended,TRUE);

    sended=FALSE;
    rebrick_clean_func_t cleanfunc2;
    cleanfunc2.func=deletesendata;
    cleanfunc2.ptr=bodybuffer;
    result=rebrick_httpsocket_send(socket,bodybuffer->buf,bodybuffer->len,cleanfunc2);
    loop(counter,1000,(!sended));
    assert_int_equal(sended,TRUE);



    loop(counter,100,!header_received);
    assert_int_equal(header_received,TRUE);
    loop(counter,100,!is_bodyreaded);
    assert_int_equal(is_bodyreaded,TRUE);
    assert_non_null(socket->header);
    assert_int_equal(socket->header->major_version,1);
    assert_int_equal(socket->header->minor_version,1);
    assert_int_equal(socket->header->is_request,FALSE);
    assert_string_equal(socket->header->path,"");
    assert_string_equal(socket->header->method,"");
    assert_string_equal(socket->header->status_code_str,"OK");
    assert_int_equal(socket->header->status_code,200);
    const char *value;
    rebrick_http_header_get_header(socket->header,"X-Powered-By",&value);
    assert_string_equal(value,"Express");
    rebrick_http_header_get_header(socket->header,"Content-Type",&value);
    assert_string_equal(value,"application/json; charset=utf-8");
    rebrick_http_header_get_header(socket->header,"Content-Length",&value);

    assert_int_equal(atoi(value),strlen(body));

     rebrick_http_header_get_header(socket->header,"Connection",&value);
    assert_string_equal(value,"keep-alive");


    assert_string_equal(readedbufferbody,body);




    rebrick_http_header_destroy(header);

    assert_int_equal(socket->content_received_length,strlen(body));
    rebrick_httpsocket_reset(socket);
    assert_int_equal(socket->content_received_length,0);
    assert_null(socket->header);
    assert_int_equal(socket->header_len,0);
    assert_int_equal(socket->is_header_parsed,0);
    assert_null(socket->tmp_buffer);

    rebrick_httpsocket_destroy(socket);
    loop(counter,100,TRUE);
}










int test_rebrick_httpsocket(void) {
    const struct CMUnitTest tests[] = {

        cmocka_unit_test(http_socket_as_client_create_get),
        cmocka_unit_test(http_socket_as_client_create_post)

    };
    return cmocka_run_group_tests(tests, setup, teardown);
}

