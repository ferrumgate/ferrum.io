#include "rebrick_httpsocket.h"

static void local_on_error_occured_callback(rebrick_socket_t *ssocket, void *callbackdata, int error) {
  unused(ssocket);
  unused(callbackdata);
  unused(error);
  rebrick_httpsocket_t *httpsocket = cast_to_httpsocket(ssocket);
  if (httpsocket) {
    if (httpsocket->override_override_on_error)
      httpsocket->override_override_on_error(cast_to_socket(httpsocket), httpsocket->override_override_callback_data, error);
  }
}

static void local_on_connection_accepted_callback(rebrick_socket_t *ssocket, void *callback_data, const struct sockaddr *addr, void *client_handle) {

  unused(ssocket);
  unused(callback_data);
  unused(addr);
  unused(client_handle);

  char current_time_str[32] = {0};
  unused(current_time_str);
  int32_t result;
  unused(result);

  rebrick_httpsocket_t *httpsocket = cast_to_httpsocket(ssocket);
  if (!httpsocket) {
    rebrick_log_fatal(__FILE__, __LINE__, "socket casting to httpsocket is null\n");
    return;
  }

  rebrick_httpsocket_t *socket = NULL;
  if (httpsocket->is_server)
    socket = cast_to_httpsocket(client_handle);
  else
    socket = httpsocket;

  if (httpsocket->is_server) {
    socket->override_override_callback_data = httpsocket->override_override_callback_data;
    socket->override_override_on_client_connect = httpsocket->override_override_on_client_connect;
    socket->override_override_on_client_close = httpsocket->override_override_on_client_close;
    socket->override_override_on_read = httpsocket->override_override_on_read;
    socket->override_override_on_write = httpsocket->override_override_on_write;
    socket->override_override_on_error = httpsocket->override_override_on_error;
    socket->on_http_body_read = httpsocket->on_http_body_read;
    socket->on_http_header_read = httpsocket->on_http_header_read;
  }

  if (httpsocket->override_override_on_client_connect)
    httpsocket->override_override_on_client_connect(cast_to_socket(httpsocket), httpsocket->override_override_callback_data, addr, socket);
}

static void local_on_connection_closed_callback(rebrick_socket_t *ssocket, void *callback_data) {
  unused(ssocket);
  unused(callback_data);
  char current_time_str[32] = {0};
  unused(current_time_str);
  int32_t result;
  unused(result);

  rebrick_httpsocket_t *httpsocket = cast_to_httpsocket(ssocket);

  if (httpsocket) {
    if (httpsocket->tmp_buffer)
      rebrick_buffer_destroy(httpsocket->tmp_buffer);

    if (httpsocket->received_header)
      rebrick_http_header_destroy(httpsocket->received_header);

    if (httpsocket->send_header)
      rebrick_http_header_destroy(httpsocket->send_header);

    if (httpsocket->override_override_on_client_close)
      httpsocket->override_override_on_client_close(cast_to_socket(httpsocket), httpsocket->override_override_callback_data);
  }
}

static void local_on_data_sended_callback(rebrick_socket_t *ssocket, void *callback_data, void *source) {
  unused(ssocket);
  unused(callback_data);
  unused(source);

  char current_time_str[32] = {0};
  unused(current_time_str);
  int32_t result;
  unused(result);

  rebrick_httpsocket_t *httpsocket = cast_to_httpsocket(ssocket);

  if (httpsocket) {

    if (httpsocket->override_override_on_write)
      httpsocket->override_override_on_write(cast_to_socket(httpsocket), httpsocket->override_override_callback_data, source);
  }
}

#define call_on_error(httpsocket, error)                                                                                    \
  if (httpsocket->override_override_on_error) {                                                                             \
    httpsocket->override_override_on_error(cast_to_socket(httpsocket), httpsocket->override_override_callback_data, error); \
  }

static void local_after_data_received_callback(rebrick_socket_t *socket, void *callback_data, const struct sockaddr *addr, const uint8_t *buffer, ssize_t len) {
  unused(socket);
  unused(callback_data);
  unused(addr);
  unused(buffer);
  unused(len);
  char current_time_str[32] = {0};
  unused(current_time_str);
  int32_t result;
  unused(result);

  if (!socket) {
    rebrick_log_fatal(__FILE__, __LINE__, "socket argument is null\n");
    return;
  }

  rebrick_httpsocket_t *httpsocket = cast_to_httpsocket(socket);

  if (httpsocket->override_override_on_read)
    httpsocket->override_override_on_read(cast_to_socket(httpsocket), httpsocket->override_override_callback_data, addr, buffer, len);

  if (httpsocket->is_header_parsed) {
    if (httpsocket->on_http_body_read) {
      httpsocket->content_received_length += len;
      httpsocket->on_http_body_read(cast_to_socket(httpsocket), 0, httpsocket->override_override_callback_data, addr,
                                    buffer, len);
    }
  } else {

    if (httpsocket->tmp_buffer) {
      result = rebrick_buffer_add(httpsocket->tmp_buffer, cast(buffer, uint8_t *), len);
    } else {
      result = rebrick_buffer_new(&httpsocket->tmp_buffer, cast(buffer, uint8_t *), len, REBRICK_HTTP_BUFFER_MALLOC);
    }

    if (result < 0) {

      call_on_error(httpsocket, result);
      return;
    }

    httpsocket->parsing_params.num_headers = sizeof(httpsocket->parsing_params.headers) / sizeof(httpsocket->parsing_params.headers[0]);
    int32_t pret = 0;
    int32_t is_request_header = FALSE;

    // check request or response
    if (httpsocket->tmp_buffer->len < 5) {
      rebrick_log_fatal(__FILE__, __LINE__, "httpsocket tmp buffer len is<5\n");
      return;
    }
    // small lower buffer of started data

    if ((httpsocket->received_header == NULL && strncasecmp(cast(httpsocket->tmp_buffer->buf, const char *), "HTTP/", 5) == 0) || (httpsocket->received_header && !httpsocket->received_header->is_request)) {
      pret = phr_parse_response(cast(httpsocket->tmp_buffer->buf, const char *),
                                httpsocket->tmp_buffer->len,
                                &httpsocket->parsing_params.minor_version,
                                &httpsocket->parsing_params.status,
                                &httpsocket->parsing_params.status_msg,
                                &httpsocket->parsing_params.status_msg_len,
                                httpsocket->parsing_params.headers,
                                &httpsocket->parsing_params.num_headers, httpsocket->parsing_params.pos);
      is_request_header = FALSE;
    } else {
      is_request_header = TRUE;
      pret = phr_parse_request(cast(httpsocket->tmp_buffer->buf, const char *),
                               httpsocket->tmp_buffer->len,
                               &httpsocket->parsing_params.method, &httpsocket->parsing_params.method_len,
                               &httpsocket->parsing_params.path, &httpsocket->parsing_params.path_len,
                               &httpsocket->parsing_params.minor_version,
                               httpsocket->parsing_params.headers, &httpsocket->parsing_params.num_headers, httpsocket->parsing_params.pos);
    }

    if (pret == -1) {
      rebrick_log_error(__FILE__, __LINE__, "header parse error\n");
      call_on_error(httpsocket, REBRICK_ERR_HTTP_HEADER_PARSE);
      return;
    }

    if (httpsocket->tmp_buffer->len >= REBRICK_HTTP_MAX_HEADER_LEN) {
      rebrick_log_error(__FILE__, __LINE__, "http max header len exceed\n");
      call_on_error(httpsocket, REBRICK_HTTP_MAX_HEADER_LEN);
      return;
    }
    httpsocket->parsing_params.pos = pret;
    if (pret > 0) {
      if (!httpsocket->received_header) {

        if (is_request_header) {
          result = rebrick_http_header_new2(&httpsocket->received_header, NULL, 0, NULL, 0,
                                            httpsocket->parsing_params.method,
                                            httpsocket->parsing_params.method_len,
                                            httpsocket->parsing_params.path,
                                            httpsocket->parsing_params.path_len,
                                            httpsocket->parsing_params.minor_version == 1 ? 1 : 2,
                                            httpsocket->parsing_params.minor_version);
        } else {
          result = rebrick_http_header_new4(&httpsocket->received_header,
                                            httpsocket->parsing_params.status,
                                            httpsocket->parsing_params.minor_version == 1 ? 1 : 2,
                                            httpsocket->parsing_params.minor_version);
        }
        if (result < 0) {
          rebrick_log_error(__FILE__, __LINE__, "new header create error\n");
          call_on_error(httpsocket, REBRICK_ERR_HTTP_HEADER_PARSE);
        }
      }

      for (size_t i = 0; i < httpsocket->parsing_params.num_headers; ++i) {
        struct phr_header *header = httpsocket->parsing_params.headers + i;
        result = rebrick_http_header_add_header2(httpsocket->received_header, cast(header->name, uint8_t *), header->name_len, cast(header->value, uint8_t *), header->value_len);
        if (result < 0) {
          rebrick_log_error(__FILE__, __LINE__, "adding header to headers error\n");
          call_on_error(httpsocket, REBRICK_ERR_HTTP_HEADER_PARSE);
        }
      }

      httpsocket->is_header_parsed = TRUE;
      httpsocket->header_len = pret;

      // http header finished
      if (httpsocket->on_http_header_read)
        httpsocket->on_http_header_read(cast_to_socket(httpsocket), 0, httpsocket->override_override_callback_data, httpsocket->received_header);

      // http upgrade protocol check
      if (httpsocket->is_server && httpsocket->on_socket_upgrade_read) {
        const char *connection_value = NULL;
        result = rebrick_http_header_get_header(httpsocket->received_header, "connection", &connection_value);
        if (!result && connection_value && strcasecmp(connection_value, "upgrade") == 0) {
          const char *upgrade = NULL;
          result = rebrick_http_header_get_header(httpsocket->received_header, "upgrade", &upgrade);
          if (!result && upgrade) {
            rebrick_upgrade_socket_type_t upgrade_type = http2;
            // http2 upgrade
            if (strcasecmp("h2c", upgrade) == 0 || strcasecmp("h2", upgrade)) {
              upgrade_type = http2;
              const char *extra_value = NULL;
              result = rebrick_http_header_get_header(httpsocket->received_header, "HTTP2-Settings", &extra_value);
              if (!result && extra_value) {
                httpsocket->on_socket_upgrade_read(cast_to_socket(httpsocket), httpsocket->override_override_callback_data, upgrade_type, httpsocket->received_header);
              }
            }

            // websocket upgrade
            if (strcasecmp("websocket", upgrade) == 0) {
              upgrade_type = websocket;
              if (!result) {
                httpsocket->on_socket_upgrade_read(cast_to_socket(httpsocket), httpsocket->override_override_callback_data, upgrade_type, httpsocket->received_header);
              }
            }
          }
        }
      }
      // if there is data after header parsed in buffer
      // call on_http_body
      if (cast(httpsocket->tmp_buffer->len, ssize_t) > pret) {
        if (httpsocket->on_http_body_read) {
          size_t length_remain = httpsocket->tmp_buffer->len - pret;
          size_t offset = httpsocket->tmp_buffer->len - length_remain;
          httpsocket->content_received_length += length_remain;
          httpsocket->on_http_body_read(cast_to_socket(httpsocket), 0, httpsocket->override_override_callback_data, addr,
                                        httpsocket->tmp_buffer->buf + offset, length_remain);
        }
      }
    }
  }
}

static struct rebrick_tcpsocket *local_create_client() {
  char current_time_str[32] = {0};
  unused(current_time_str);
  rebrick_httpsocket_t *client = new1(rebrick_httpsocket_t);
  constructor(client, rebrick_httpsocket_t);
  return cast_to_tcpsocket(client);
}
/*static int copied_from_nghttp2_select_next_protocol(unsigned char **out, unsigned char *outlen,
                                const unsigned char *in, unsigned int inlen,
                                const char *key, unsigned int keylen) {
  unsigned int i;
  for (i = 0; i + keylen <= inlen; i += (unsigned int)(in[i] + 1)) {
    if (memcmp(&in[i], key, keylen) == 0) {
      *out = (unsigned char *)&in[i + 1];
      *outlen = in[i];
      return 0;
    }
  }
  return -1;
}*/

static int rebrick_tls_alpn_select_callback(unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen) {
  unused(out);
  unused(outlen);
  unused(in);
  unused(inlen);

  int rv;
  rv = SSL_select_next_proto(cast(out, unsigned char **), outlen, in, inlen, cast(REBRICK_HTTP_ALPN_PROTO, const unsigned char *), REBRIKC_HTTP_ALPN_PROTO_LEN);
  // rv = copied_from_nghttp2_select_next_protocol(cast(out,unsigned char**), outlen, in, inlen,cast(REBRICK_HTTP_ALPN_PROTO,const char*),REBRIKC_HTTP_ALPN_PROTO_LEN);

  if (rv == -1) {
    return SSL_TLSEXT_ERR_NOACK;
  }

  return SSL_TLSEXT_ERR_OK;
}

int32_t rebrick_httpsocket_init(rebrick_httpsocket_t *httpsocket,
                                const char *sni_pattern_or_name,
                                rebrick_tls_context_t *tls_context,
                                const rebrick_sockaddr_t *bind_addr,
                                const rebrick_sockaddr_t *peer_addr,
                                int32_t backlog_or_isclient, rebrick_tcpsocket_create_client_t create_client,
                                const rebrick_httpsocket_callbacks_t *callbacks)

{
  char current_time_str[32] = {0};
  unused(current_time_str);
  int32_t result;
  unused(result);
  httpsocket->override_override_tls_context = tls_context;

  new2(rebrick_tlssocket_callbacks_t, local_callbacks);
  local_callbacks.on_client_connect = local_on_connection_accepted_callback;
  local_callbacks.on_client_close = local_on_connection_closed_callback;
  local_callbacks.on_read = local_after_data_received_callback;
  local_callbacks.on_write = local_on_data_sended_callback;
  local_callbacks.on_error = local_on_error_occured_callback;

  if (tls_context || (sni_pattern_or_name && strlen(sni_pattern_or_name))) {
    result = rebrick_tlssocket_init(cast_to_tlssocket(httpsocket), sni_pattern_or_name, tls_context, bind_addr, peer_addr, backlog_or_isclient, create_client, &local_callbacks);
    if (!result && tls_context && !tls_context->alpn_select_callback) {
      result = rebrick_tls_context_set_alpn_protos(tls_context, REBRICK_HTTP_ALPN_PROTO, REBRIKC_HTTP_ALPN_PROTO_LEN, rebrick_tls_alpn_select_callback);
      result |= rebrick_tls_context_set_npn_protos(tls_context, REBRICK_HTTP_ALPN_PROTO, REBRIKC_HTTP_ALPN_PROTO_LEN, rebrick_tls_alpn_select_callback);
    }
  } else {

    result = rebrick_tcpsocket_init(cast_to_tcpsocket(httpsocket), bind_addr, peer_addr, backlog_or_isclient, create_client, cast_to_tcpsocket_callbacks(&local_callbacks));
  }
  if (result < 0) {
    rebrick_log_error(__FILE__, __LINE__, "http socket creation failed with eror:%d\n", result);
    return result;
  }
  httpsocket->override_override_on_client_connect = callbacks ? callbacks->on_client_connect : NULL;
  httpsocket->override_override_on_client_close = callbacks ? callbacks->on_client_close : NULL;
  httpsocket->override_override_on_read = callbacks ? callbacks->on_read : NULL;
  httpsocket->override_override_on_write = callbacks ? callbacks->on_write : NULL;
  httpsocket->override_override_on_error = callbacks ? callbacks->on_error : NULL;
  httpsocket->override_override_callback_data = callbacks ? callbacks->callback_data : NULL;
  httpsocket->on_http_header_read = callbacks ? callbacks->on_http_header_read : NULL;
  httpsocket->on_http_body_read = callbacks ? callbacks->on_http_body_read : NULL;
  httpsocket->on_socket_upgrade_read = callbacks ? callbacks->on_socket_upgrade_read : NULL;

  return REBRICK_SUCCESS;
}

int32_t rebrick_httpsocket_new(rebrick_httpsocket_t **socket,
                               const char *sni_pattern_or_name,
                               rebrick_tls_context_t *tls_context,
                               const rebrick_sockaddr_t *bind_addr,
                               const rebrick_sockaddr_t *peer_addr,
                               int32_t backlog_or_isclient, const rebrick_httpsocket_callbacks_t *callbacks) {

  char current_time_str[32] = {0};
  unused(current_time_str);
  int32_t result;
  unused(result);
  rebrick_httpsocket_t *httpsocket = new1(rebrick_httpsocket_t);
  constructor(httpsocket, rebrick_httpsocket_t);

  result = rebrick_httpsocket_init(httpsocket, sni_pattern_or_name, tls_context, bind_addr, peer_addr,
                                   backlog_or_isclient, local_create_client, callbacks);
  if (result < 0) {
    rebrick_log_error(__FILE__, __LINE__, "http socket init failed with error:%d\n", result);
    rebrick_free(httpsocket);
    return result;
  }
  *socket = httpsocket;
  return REBRICK_SUCCESS;
}

int32_t rebrick_httpsocket_destroy(rebrick_httpsocket_t *socket) {
  unused(socket);
  if (socket) {
    if (socket->override_override_tls_context) {
      return rebrick_tlssocket_destroy(cast_to_tlssocket(socket));
    } else {
      return rebrick_tcpsocket_destroy(cast_to_tcpsocket(socket));
    }
  }
  return REBRICK_SUCCESS;
}

int32_t rebrick_httpsocket_reset(rebrick_httpsocket_t *socket) {
  if (socket) {
    if (socket->tmp_buffer)
      rebrick_buffer_destroy(socket->tmp_buffer);
    socket->tmp_buffer = NULL;

    if (socket->received_header)
      rebrick_http_header_destroy(socket->received_header);
    if (socket->send_header)
      rebrick_http_header_destroy(socket->send_header);
    socket->received_header = NULL;
    socket->send_header = NULL;
    socket->is_header_parsed = FALSE;

    socket->content_received_length = 0;
    socket->header_len = 0;
  }

  return REBRICK_SUCCESS;
}
int32_t rebrick_httpsocket_write(rebrick_httpsocket_t *socket, uint8_t *buffer, size_t len, rebrick_clean_func_t cleanfunc) {
  unused(socket);
  unused(buffer);
  unused(len);
  unused(cleanfunc);

  if (!socket || !buffer | !len)
    return REBRICK_ERR_BAD_ARGUMENT;

  if (socket->tls)
    return rebrick_tlssocket_write(cast_to_tlssocket(socket), buffer, len, cleanfunc);
  return rebrick_tcpsocket_write(cast_to_tcpsocket(socket), buffer, len, cleanfunc);
}

static void clean_buffer(void *buffer) {
  rebrick_buffer_t *tmp = cast(buffer, rebrick_buffer_t *);
  if (tmp) {
    rebrick_buffer_destroy(tmp);
  }
}

int32_t rebrick_httpsocket_write_header(rebrick_httpsocket_t *socket, int32_t *stream_id, int64_t flags, rebrick_http_header_t *header) {
  unused(socket);
  int32_t result;
  char current_time_str[32] = {0};
  unused(current_time_str);
  // not used, only for compability with http2
  unused(stream_id);
  unused(flags);
  if (!socket || !header)
    return REBRICK_ERR_BAD_ARGUMENT;

  rebrick_buffer_t *buffer;
  result = rebrick_http_header_to_http_buffer(header, &buffer);
  if (result < 0) {
    rebrick_log_error(__FILE__, __LINE__, "http sending header failed with error:%d\n", result);
    return result;
  }
  /// save current sended header
  if (socket->send_header)
    rebrick_http_header_destroy(socket->send_header);
  socket->send_header = header;
  rebrick_clean_func_t cleanfunc = {.func = clean_buffer, .ptr = buffer};
  return rebrick_httpsocket_write(socket, buffer->buf, buffer->len, cleanfunc);
}
int32_t rebrick_httpsocket_write_body(rebrick_httpsocket_t *socket, int32_t stream_id, int64_t flags, uint8_t *buffer, size_t len, rebrick_clean_func_t cleanfunc) {
  unused(socket);
  int32_t result;
  unused(result);
  char current_time_str[32] = {0};
  // this parameter is significant for http2
  unused(stream_id);
  // this parameter is significant for http2
  unused(flags);
  unused(current_time_str);
  if (!socket || !buffer)
    return REBRICK_ERR_BAD_ARGUMENT;

  return rebrick_httpsocket_write(socket, buffer, len, cleanfunc);
}