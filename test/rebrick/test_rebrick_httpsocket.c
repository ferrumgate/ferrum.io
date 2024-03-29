#include "./rebrick/http/rebrick_httpsocket.h"
#include "cmocka.h"
#include <unistd.h>

#define loop(var, a, x)                       \
  var = a;                                    \
  while (var-- && (x)) {                      \
    usleep(100);                              \
    uv_run(uv_default_loop(), UV_RUN_NOWAIT); \
  }

static rebrick_tls_context_t *context_verify_none = NULL;
static rebrick_tls_context_t *context_hamzakilic_com = NULL;
static int setup(void **state) {
  unused(state);
  int32_t result;
  rebrick_tls_init();
  rebrick_tls_context_new(&context_verify_none, "client", SSL_VERIFY_NONE, SSL_SESS_CACHE_BOTH, SSL_OP_ALL, 0, NULL, NULL);
  result = rebrick_tls_context_new(&context_hamzakilic_com, "hamzakilic.com", SSL_VERIFY_NONE, SSL_SESS_CACHE_OFF, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TICKET, SSL_OP_NO_COMPRESSION, "./rebrick/data/domain.crt", "./rebrick/data/domain.key");

  assert_int_equal(result, REBRICK_SUCCESS);
  fprintf(stdout, "****  %s ****\n", __FILE__);
  return 0;
}

static int teardown(void **state) {
  unused(state);
  int32_t loop_counter;
  rebrick_tls_context_destroy(context_verify_none);
  context_verify_none = NULL;
  rebrick_tls_context_destroy(context_hamzakilic_com);
  context_hamzakilic_com = NULL;
  rebrick_tls_cleanup();
  loop(loop_counter, 100, TRUE);
  uv_loop_close(uv_default_loop());
  return 0;
}

static void on_error_occured_callback(rebrick_socket_t *socket, void *callback, int error) {
  unused(socket);
  unused(callback);
  unused(error);
  rebrick_tlssocket_destroy(cast(socket, rebrick_tlssocket_t *));
}

static int32_t is_connected = FALSE;
rebrick_httpsocket_t *client;
static void on_connection_accepted_callback(rebrick_socket_t *socket, void *callback_data, const struct sockaddr *addr, void *client_handle) {
  is_connected = TRUE;

  unused(callback_data);
  unused(addr);
  unused(client_handle);
  unused(socket);
  client = cast_to_httpsocket(client_handle);
}
static int32_t is_connection_closed = 0;
static void on_connection_closed_callback(rebrick_socket_t *socket, void *callback_data) {
  unused(callback_data);
  unused(socket);
  is_connection_closed = 1;
}
static int32_t is_datareaded = FALSE;
static int32_t totalreaded_len = 0;
static char readedbuffer[131072] = {0};
static void on_data_read_callback(rebrick_socket_t *socket, void *callback_data, const struct sockaddr *addr, const uint8_t *buffer, ssize_t len) {
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
static int32_t sended = FALSE;
static void on_data_send(rebrick_socket_t *socket, void *callback, void *source) {
  unused(socket);
  unused(callback);
  unused(source);

  sended = TRUE;
}
static int32_t header_received = FALSE;
static void on_http_header_received(rebrick_socket_t *socket, int32_t stream_id, void *callback_data, rebrick_http_header_t *header) {
  unused(socket);
  unused(callback_data);
  unused(header);
  // stream id is useless, at least this is not http2
  unused(stream_id);

  header_received = TRUE;
}

static int32_t is_bodyreaded = FALSE;
static int32_t totalreadedbody_len = 0;
static char readedbufferbody[131072] = {0};
static void on_body_read_callback(rebrick_socket_t *socket, int32_t stream_id, void *callback_data, const struct sockaddr *addr, const uint8_t *buffer, ssize_t len) {
  unused(addr);
  unused(socket);
  unused(addr);
  unused(buffer);
  unused(len);
  // this is http, stream id is allways zero
  unused(stream_id);
  unused(callback_data);

  is_bodyreaded = TRUE;
  fill_zero(readedbufferbody, sizeof(readedbufferbody));

  memcpy(readedbufferbody, buffer, len);

  totalreadedbody_len += len;
}

void deletesendata(void *ptr) {
  if (ptr) {
    rebrick_buffer_t *buffer = cast(ptr, rebrick_buffer_t *);
    rebrick_buffer_destroy(buffer);
  }
}

static void http_socket_as_client_create_get(void **start) {
  unused(start);
  int32_t result;
  int32_t counter;

  rebrick_sockaddr_t destination;

  rebrick_util_ip_port_to_addr("127.0.0.1", "9090", &destination);

  rebrick_httpsocket_t *socket;
  is_connected = FALSE;

  new2(rebrick_httpsocket_callbacks_t, callbacks);
  callbacks.on_client_connect = on_connection_accepted_callback;
  callbacks.on_client_close = on_connection_closed_callback;
  callbacks.on_read = on_data_read_callback;
  callbacks.on_write = on_data_send;
  callbacks.on_error = on_error_occured_callback;
  callbacks.on_http_body_read = on_body_read_callback;
  callbacks.on_http_header_read = on_http_header_received;

  result = rebrick_httpsocket_new(&socket, NULL, NULL, NULL, &destination, 0, &callbacks);
  assert_int_equal(result, 0);

  loop(counter, 1000, !is_connected);
  assert_int_equal(is_connected, TRUE);

  rebrick_http_header_t *header;
  result = rebrick_http_header_new(&header, "http", "localhost", "GET", "/api/get", 1, 1);
  assert_int_equal(result, REBRICK_SUCCESS);

  sended = FALSE;
  header_received = FALSE;
  is_bodyreaded = FALSE;

  // send data
  int stream_id = 0;
  result = rebrick_httpsocket_write_header(socket, &stream_id, 0, header);
  assert_int_equal(result, REBRICK_SUCCESS);
  loop(counter, 1000, (!sended));
  assert_int_equal(sended, TRUE);
  loop(counter, 100, !header_received);
  assert_int_equal(header_received, TRUE);
  loop(counter, 100, !is_bodyreaded);
  assert_int_equal(is_bodyreaded, TRUE);
  assert_non_null(socket->received_header);
  assert_int_equal(socket->received_header->major_version, 1);
  assert_int_equal(socket->received_header->minor_version, 1);
  assert_int_equal(socket->received_header->is_request, FALSE);
  assert_string_equal(socket->received_header->path, "");
  assert_string_equal(socket->received_header->method, "");
  assert_string_equal(socket->received_header->status_code_str, "OK");
  assert_int_equal(socket->received_header->status_code, 200);
  const char *value;
  rebrick_http_header_get_header(socket->received_header, "X-Powered-By", &value);
  assert_string_equal(value, "Express");
  rebrick_http_header_get_header(socket->received_header, "Content-Type", &value);
  assert_string_equal(value, "text/html; charset=utf-8");
  rebrick_http_header_get_header(socket->received_header, "Content-Length", &value);
  assert_string_equal(value, "10");
  /*rebrick_http_header_get_header(socket->header,"ETag",&value);
  assert_string_equal(value,"W/\"19-EE0dTSKO8nU0PWVui0tLx8f6m9I\"");
   rebrick_http_header_get_header(socket->header,"Date",&value);
  assert_string_equal(value,"Sun, 22 Sep 2019 20:14:00 GMT");*/
  rebrick_http_header_get_header(socket->received_header, "Connection", &value);
  assert_string_equal(value, "keep-alive");

  assert_string_equal(readedbufferbody, "hello http");
  assert_memory_equal(header, socket->send_header, sizeof(rebrick_http_header_t));

  assert_int_equal(socket->content_received_length, 10);
  rebrick_httpsocket_reset(socket);
  assert_int_equal(socket->content_received_length, 0);
  assert_null(socket->received_header);
  assert_null(socket->send_header);
  assert_int_equal(socket->header_len, 0);
  assert_int_equal(socket->is_header_parsed, 0);
  assert_null(socket->tmp_buffer);

  rebrick_httpsocket_destroy(socket);
  loop(counter, 100, TRUE);
}

static void http_socket_as_client_create_post(void **start) {
  unused(start);
  int32_t result;
  int32_t counter = 0;

  rebrick_sockaddr_t destination;

  rebrick_util_ip_port_to_addr("127.0.0.1", "9090", &destination);

  rebrick_httpsocket_t *socket;
  is_connected = FALSE;

  new2(rebrick_httpsocket_callbacks_t, callbacks);
  callbacks.on_client_connect = on_connection_accepted_callback;
  callbacks.on_client_close = on_connection_closed_callback;
  callbacks.on_read = on_data_read_callback;
  callbacks.on_write = on_data_send;
  callbacks.on_error = on_error_occured_callback;
  callbacks.on_http_body_read = on_body_read_callback;
  callbacks.on_http_header_read = on_http_header_received;

  result = rebrick_httpsocket_new(&socket, NULL, NULL, NULL, &destination, 0, &callbacks);
  assert_int_equal(result, REBRICK_SUCCESS);

  loop(counter, 10000, !is_connected);
  assert_int_equal(is_connected, TRUE);

  char temp[1024];
  // body buffer
  const char *body = "{\"hello\":\"world\"}";
  rebrick_buffer_t *bodybuffer;
  result = rebrick_buffer_new(&bodybuffer, cast_to_uint8ptr(body), strlen(body), 64);
  assert_int_equal(result, REBRICK_SUCCESS);

  rebrick_http_header_t *header;
  result = rebrick_http_header_new(&header, "http", "localhost", "POST", "/api/post", 1, 1);
  assert_int_equal(result, REBRICK_SUCCESS);
  rebrick_http_header_add_header(header, "content-type", "application/json");
  sprintf(temp, "%ld", bodybuffer->len);
  rebrick_http_header_add_header(header, "content-length", temp);
  // header buffer

  sended = FALSE;
  header_received = FALSE;
  is_bodyreaded = FALSE;

  int32_t stream_id = 0;
  result = rebrick_httpsocket_write_header(socket, &stream_id, 0, header);
  assert_int_equal(result, REBRICK_SUCCESS);
  loop(counter, 1000, (!sended));
  assert_int_equal(sended, TRUE);

  sended = FALSE;
  rebrick_clean_func_t cleanfunc2;
  cleanfunc2.func = deletesendata;
  cleanfunc2.ptr = bodybuffer;
  result = rebrick_httpsocket_write(socket, bodybuffer->buf, bodybuffer->len, cleanfunc2);
  loop(counter, 1000, (!sended));
  assert_int_equal(sended, TRUE);

  loop(counter, 100, !header_received);
  assert_int_equal(header_received, TRUE);
  loop(counter, 100, !is_bodyreaded);
  assert_int_equal(is_bodyreaded, TRUE);
  assert_non_null(socket->received_header);
  assert_int_equal(socket->received_header->major_version, 1);
  assert_int_equal(socket->received_header->minor_version, 1);
  assert_int_equal(socket->received_header->is_request, FALSE);
  assert_string_equal(socket->received_header->path, "");
  assert_string_equal(socket->received_header->method, "");
  assert_string_equal(socket->received_header->status_code_str, "OK");
  assert_int_equal(socket->received_header->status_code, 200);
  const char *value;
  rebrick_http_header_get_header(socket->received_header, "X-Powered-By", &value);
  assert_string_equal(value, "Express");
  rebrick_http_header_get_header(socket->received_header, "Content-Type", &value);
  assert_string_equal(value, "application/json; charset=utf-8");
  rebrick_http_header_get_header(socket->received_header, "Content-Length", &value);

  assert_int_equal(atoi(value), strlen(body));

  rebrick_http_header_get_header(socket->received_header, "Connection", &value);
  assert_string_equal(value, "keep-alive");

  assert_string_equal(readedbufferbody, body);

  assert_int_equal(socket->content_received_length, strlen(body));
  rebrick_httpsocket_reset(socket);
  assert_int_equal(socket->content_received_length, 0);
  assert_null(socket->received_header);
  assert_int_equal(socket->header_len, 0);
  assert_int_equal(socket->is_header_parsed, 0);
  assert_null(socket->tmp_buffer);

  rebrick_httpsocket_destroy(socket);
  loop(counter, 100, TRUE);
}

static void http_socket_as_client_create_with_tls_post(void **start) {
  unused(start);
  int32_t result;
  int32_t counter = 0;

  rebrick_sockaddr_t destination;

  rebrick_util_ip_port_to_addr("127.0.0.1", "9191", &destination);

  rebrick_httpsocket_t *socket;
  is_connected = FALSE;

  new2(rebrick_httpsocket_callbacks_t, callbacks);
  callbacks.on_client_connect = on_connection_accepted_callback;
  callbacks.on_client_close = on_connection_closed_callback;
  callbacks.on_read = on_data_read_callback;
  callbacks.on_write = on_data_send;
  callbacks.on_error = on_error_occured_callback;
  callbacks.on_http_body_read = on_body_read_callback;
  callbacks.on_http_header_read = on_http_header_received;

  result = rebrick_httpsocket_new(&socket, NULL, context_verify_none, NULL, &destination, 0, &callbacks);
  assert_int_equal(result, REBRICK_SUCCESS);

  loop(counter, 10000, !is_connected);
  assert_int_equal(is_connected, TRUE);

  char temp[1024];
  // body buffer
  const char *body = "{\"hello\":\"world\"}";
  rebrick_buffer_t *bodybuffer;
  result = rebrick_buffer_new(&bodybuffer, cast_to_uint8ptr(body), strlen(body), 64);
  assert_int_equal(result, REBRICK_SUCCESS);

  rebrick_http_header_t *header;
  result = rebrick_http_header_new(&header, "https", "localhost", "POST", "/api/post", 1, 1);
  assert_int_equal(result, REBRICK_SUCCESS);
  rebrick_http_header_add_header(header, "content-type", "application/json");
  sprintf(temp, "%ld", bodybuffer->len);
  rebrick_http_header_add_header(header, "content-length", temp);

  sended = FALSE;
  header_received = FALSE;
  is_bodyreaded = FALSE;

  int32_t stream_id = 0;

  result = rebrick_httpsocket_write_header(socket, &stream_id, 0, header);
  assert_int_equal(result, REBRICK_SUCCESS);
  loop(counter, 10000, (!sended));
  assert_int_equal(sended, TRUE);

  sended = FALSE;
  rebrick_clean_func_t cleanfunc2;
  cleanfunc2.func = deletesendata;
  cleanfunc2.ptr = bodybuffer;
  result = rebrick_httpsocket_write_body(socket, 0, 0, bodybuffer->buf, bodybuffer->len, cleanfunc2);
  assert_int_equal(result, REBRICK_SUCCESS);
  loop(counter, 1000, (!sended));
  assert_int_equal(sended, TRUE);

  loop(counter, 1000, !header_received);
  assert_int_equal(header_received, TRUE);
  loop(counter, 1000, !is_bodyreaded);
  assert_int_equal(is_bodyreaded, TRUE);
  assert_non_null(socket->received_header);
  assert_int_equal(socket->received_header->major_version, 1);
  assert_int_equal(socket->received_header->minor_version, 1);
  assert_int_equal(socket->received_header->is_request, FALSE);
  assert_string_equal(socket->received_header->path, "");
  assert_string_equal(socket->received_header->method, "");
  assert_string_equal(socket->received_header->status_code_str, "OK");
  assert_int_equal(socket->received_header->status_code, 200);
  const char *value;
  rebrick_http_header_get_header(socket->received_header, "X-Powered-By", &value);
  assert_string_equal(value, "Express");
  rebrick_http_header_get_header(socket->received_header, "Content-Type", &value);
  assert_string_equal(value, "application/json; charset=utf-8");
  rebrick_http_header_get_header(socket->received_header, "Content-Length", &value);

  assert_int_equal(atoi(value), strlen(body));

  rebrick_http_header_get_header(socket->received_header, "Connection", &value);
  assert_string_equal(value, "keep-alive");

  assert_string_equal(readedbufferbody, body);

  assert_int_equal(socket->content_received_length, strlen(body));
  rebrick_httpsocket_reset(socket);
  assert_int_equal(socket->content_received_length, 0);
  assert_null(socket->received_header);
  assert_int_equal(socket->header_len, 0);
  assert_int_equal(socket->is_header_parsed, 0);
  assert_null(socket->tmp_buffer);

  rebrick_httpsocket_destroy(socket);
  loop(counter, 100, TRUE);
}

static void http_socket_as_server_get(void **tls) {
  unused(tls);
  int32_t result;
  int32_t counter = 0;

  rebrick_sockaddr_t destination;

  if (!*tls)
    rebrick_util_ip_port_to_addr("127.0.0.1", "9091", &destination);
  else
    rebrick_util_ip_port_to_addr("127.0.0.1", "9092", &destination);

  rebrick_httpsocket_t *socket;
  is_connected = FALSE;
  header_received = FALSE;
  client = NULL;

  new2(rebrick_httpsocket_callbacks_t, callbacks);
  callbacks.on_client_connect = on_connection_accepted_callback;
  callbacks.on_client_close = on_connection_closed_callback;
  callbacks.on_read = on_data_read_callback;
  callbacks.on_write = on_data_send;
  callbacks.on_error = on_error_occured_callback;
  callbacks.on_http_body_read = on_body_read_callback;
  callbacks.on_http_header_read = on_http_header_received;

  if (!*tls)
    result = rebrick_httpsocket_new(&socket, NULL, NULL, &destination, NULL, 10, &callbacks);
  else
    result = rebrick_httpsocket_new(&socket, NULL, context_hamzakilic_com, &destination, NULL, 10, &callbacks);

  if (!*tls)
    printf("for test curl -v http://localhost:9090\n");
  else
    printf("for test curl -v --insecure https://localhost:9092\n");

  assert_int_equal(result, REBRICK_SUCCESS);

  loop(counter, 100000, !is_connected);

  loop(counter, 1000, !header_received);
  if (header_received && client) {
    printf("header received\n");

    char temp[1024];
    // body buffer
    const char *body = "{\"hello\":\"world\"}";
    rebrick_buffer_t *bodybuffer;
    result = rebrick_buffer_new(&bodybuffer, cast_to_uint8ptr(body), strlen(body), 64);
    assert_int_equal(result, REBRICK_SUCCESS);

    rebrick_http_header_t *header;
    result = rebrick_http_header_new3(&header, 200, 1, 1);
    assert_int_equal(result, REBRICK_SUCCESS);
    rebrick_http_header_add_header(header, "content-type", "text/plain");
    sprintf(temp, "%ld", bodybuffer->len);
    rebrick_http_header_add_header(header, "content-length", temp);

    // header buffer

    sended = FALSE;
    header_received = FALSE;
    is_bodyreaded = FALSE;

    int32_t stream_id = 0;
    result = rebrick_httpsocket_write_header(client, &stream_id, 0, header);
    assert_int_equal(result, REBRICK_SUCCESS);
    loop(counter, 1000, (!sended));
    assert_int_equal(sended, TRUE);

    sended = FALSE;

    result = rebrick_httpsocket_write(client, bodybuffer->buf, bodybuffer->len, (rebrick_clean_func_t){.func = deletesendata, .ptr = bodybuffer});
    loop(counter, 1000, (!sended));
    assert_int_equal(sended, TRUE);
  }

  rebrick_httpsocket_destroy(socket);
  loop(counter, 100, TRUE);
}

static void http_socket_as_server_get_tls(void **start) {
  unused(start);
  int32_t tmp = 10;
  int *val = &tmp;
  http_socket_as_server_get(cast(&val, void **));
}

int test_rebrick_httpsocket(void) {
  const struct CMUnitTest tests[] = {

      cmocka_unit_test(http_socket_as_client_create_get),
      cmocka_unit_test(http_socket_as_client_create_post),
      cmocka_unit_test(http_socket_as_client_create_with_tls_post),
      cmocka_unit_test(http_socket_as_server_get),
      cmocka_unit_test(http_socket_as_server_get_tls),

  };
  return cmocka_run_group_tests(tests, setup, teardown);
}
