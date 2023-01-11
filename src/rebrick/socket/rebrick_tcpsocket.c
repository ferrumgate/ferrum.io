#include "rebrick_tcpsocket.h"

static void on_close(uv_handle_t *handle);

static void on_send(uv_write_t *req, int status) {
  char current_time_str[32] = {0};
  unused(current_time_str);
  rebrick_log_debug("socket on send called and status:%d\n", status);

  rebrick_clean_func_t *clean_func = cast(req->data, rebrick_clean_func_t *);
  void *source = clean_func ? clean_func->anydata.ptr : NULL;
  if (req->handle && req->handle->data) {
    const rebrick_tcpsocket_t *socket = cast_to_tcpsocket(req->handle->data);

    if (status < 0) {
      if (socket->on_error)
        socket->on_error(cast_to_socket(socket), socket->callback_data, REBRICK_ERR_UV + status);
    } else if (socket->on_write)
      socket->on_write(cast_to_socket(socket), socket->callback_data, source);
  }

  if (clean_func) {
    if (clean_func->func) {
      clean_func->func(clean_func->ptr);
    }
    rebrick_free(clean_func);
  }

  rebrick_free(req);
}

int32_t rebrick_tcpsocket_write(rebrick_tcpsocket_t *socket, uint8_t *buffer, size_t len, rebrick_clean_func_t cleanfunc) {

  char current_time_str[32] = {0};
  unused(current_time_str);
  int32_t result;
  if (uv_is_closing(cast(&socket->handle.tcp, uv_handle_t *))) {
    return REBRICK_ERR_IO_CLOSED;
  }

  uv_write_t *request = new1(uv_write_t);
  if_is_null_then_die(request, "malloc problem\n");
  fill_zero(request, sizeof(uv_write_t));
  uv_buf_t buf = uv_buf_init(cast(buffer, char *), len);

  rebrick_clean_func_clone(&cleanfunc, request->data);

  result = uv_write(request, cast(&socket->handle.tcp, uv_stream_t *), &buf, 1, on_send);
  if (result < 0) {
    rebrick_log_info("sending data to  %s port:%s failed: %s\n", socket->peer_ip, socket->peer_port, uv_strerror(result));
    rebrick_free(request->data);
    rebrick_free(request);
    return REBRICK_ERR_UV + result;
  }
  rebrick_log_debug("data sended  len:%zu to   %s port:%s\n", len, socket->peer_ip, socket->peer_port);
  return REBRICK_SUCCESS;
}

static void on_recv(uv_stream_t *handle, ssize_t nread, const uv_buf_t *rcvbuf) {

  char current_time_str[32] = {0};
  unused(current_time_str);

  const rebrick_tcpsocket_t *socket = cast_to_tcpsocket(handle->data);

  if (nread < 0) {
    if (socket->on_error) {
      rebrick_log_debug("socket error occured %zd\n", nread);
      socket->on_error(cast_to_socket(socket), socket->callback_data, REBRICK_ERR_UV + nread);
    }
  } else if (socket->on_read && nread) {
    rebrick_log_debug("socket receive nread:%zd buflen:%zu\n", nread, rcvbuf->len);
    socket->on_read(cast_to_socket(socket), socket->callback_data, NULL, cast(rcvbuf->base, uint8_t *), nread);
  }
  if (rcvbuf->base)
    rebrick_free(rcvbuf->base);
}

static void on_alloc(uv_handle_t *client, size_t suggested_size, uv_buf_t *buf) {
  unused(client);
  char current_time_str[32] = {0};
  unused(current_time_str);
  if (suggested_size <= 0) {
    rebrick_log_info("socket suggested_size is 0 from \n");
    return;
  }

  buf->base = rebrick_malloc(suggested_size);
  if_is_null_then_die(buf->base, "malloc problem\n");
  buf->len = suggested_size;
  fill_zero(buf->base, buf->len);
  rebrick_log_debug("malloc socket:%lu %p\n", buf->len, buf->base);
}

/**
 * @brief client connection
 *
 * @param connection
 * @param status
 */

static void on_connect(uv_connect_t *connection, int status) {
  char current_time_str[32] = {0};
  unused(current_time_str);

  rebrick_tcpsocket_t *socket = cast_to_tcpsocket(connection->data);

  if (socket) {
    if (status < 0) {
      if (socket->on_error)
        socket->on_error(cast_to_socket(socket), socket->callback_data, REBRICK_ERR_UV + status);
    } else if (socket->on_connect) {
      socket->on_connect(cast_to_socket(socket), socket->callback_data);
    }
  }

  rebrick_free(connection);
}

static rebrick_tcpsocket_t *create_client() {
  char current_time_str[32] = {0};
  unused(current_time_str);
  rebrick_tcpsocket_t *client = new1(rebrick_tcpsocket_t);
  constructor(client, rebrick_tcpsocket_t);
  return client;
}
/**
 * @brief on new client connection received
 *
 * @param server
 * @param status
 */
static void on_client_connected(uv_stream_t *server, int status) {
  char current_time_str[32] = {0};
  unused(current_time_str);

  int32_t result;
  int32_t temp = 0;
  if (!server) {
    rebrick_log_fatal("server parameter is null\n");
    return;
  }

  uv_tcp_t *tcp = cast(server, uv_tcp_t *);
  rebrick_tcpsocket_t *serversocket = cast_to_tcpsocket(tcp->data);

  if (status < 0) {
    rebrick_log_debug("error on_new_connection\n");
    if (server && serversocket->on_error)
      serversocket->on_error(cast_to_socket(serversocket), serversocket->callback_data, REBRICK_ERR_UV + status);
    return;
  }

  // burayı override etmeyi başarsak//ssl için yol açmış oluruz

  rebrick_tcpsocket_t *client = serversocket->create_client();

  uv_tcp_init(uv_default_loop(), &client->handle.tcp);

  result = uv_accept(server, cast(&client->handle.tcp, uv_stream_t *));
  if (result < 0) {
    // TODO: make it threadsafe
    rebrick_log_fatal("accept error uverror:%d %s\n", result, uv_strerror(result));
    // burada client direk free edilebilmeli
    // başka bir şey olmadan
    //@see rebrick_tcpsocket.h
    rebrick_free(client);

    return;
  }
  temp = sizeof(struct sockaddr_storage);
  result = uv_tcp_getpeername(&client->handle.tcp, &client->bind_addr.base, &temp);

  rebrick_util_addr_to_ip_string(&client->bind_addr, client->peer_ip);
  rebrick_util_addr_to_port_string(&client->bind_addr, client->peer_port);
  rebrick_log_debug("connected client from %s:%s\n", client->peer_ip, client->peer_port);

  client->handle.tcp.data = client;
  client->on_close = serversocket->on_client_close;
  client->on_read = serversocket->on_read;
  client->on_write = serversocket->on_write;
  client->callback_data = serversocket->callback_data;
  client->on_error = serversocket->on_error;
  client->is_server = FALSE;
  client->start_reading_immediately = serversocket->start_reading_immediately;
  client->loop = serversocket->loop;

  if (serversocket->on_client_connect) {
    serversocket->on_client_connect(cast_to_socket(serversocket), client->callback_data, &client->bind_addr.base, client);
  }
  if (serversocket->start_reading_immediately) {
    // start reading client
    result = rebrick_tcpsocket_start_reading(client);
    if (result) { // error
      rebrick_log_error("client socket start reading failed %d\n", result);
    }
  }
}

int32_t rebrick_tcpsocket_start_reading(rebrick_tcpsocket_t *socket) {
  // start reading
  int32_t result;
  if (socket->is_reading_started)
    return REBRICK_SUCCESS;
  uv_stream_t *tmp = cast(&socket->handle.tcp, uv_stream_t *);
  result = uv_read_start(tmp, on_alloc, on_recv);
  if (result)
    return REBRICK_ERR_UV + result;
  socket->is_reading_started = TRUE;
  return REBRICK_SUCCESS;
}

int32_t rebrick_tcpsocket_stop_reading(rebrick_tcpsocket_t *socket) {
  // stop reading
  int32_t result;
  if (!socket->is_reading_started)
    return REBRICK_SUCCESS;
  uv_stream_t *tmp = cast(&socket->handle.tcp, uv_stream_t *);
  result = uv_read_stop(tmp);
  if (result)
    return REBRICK_ERR_UV + result;
  socket->is_reading_started = FALSE;
  return REBRICK_SUCCESS;
}
int32_t rebrick_tcpsocket_write_buffer_size(rebrick_tcpsocket_t *socket, size_t *size) {
  uv_stream_t *tmp = cast(&socket->handle.tcp, uv_stream_t *);
  *size = uv_stream_get_write_queue_size(tmp);
  return REBRICK_SUCCESS;
}

static int32_t create_client_socket(rebrick_tcpsocket_t *socket) {
  char current_time_str[32] = {0};
  unused(current_time_str);
  int32_t result;

  socket->loop = uv_default_loop();
  result = uv_tcp_init(socket->loop, &socket->handle.tcp);
  if (result < 0) {
    // TODO: make it thread safe
    rebrick_log_fatal("socket failed:%s\n", uv_strerror(result));
    return REBRICK_ERR_UV + result;
  }
  uv_tcp_keepalive(&socket->handle.tcp, 1, 60);
  uv_connect_t *connect = new1(uv_connect_t);
  if_is_null_then_die(connect, "malloc problem\n");
  connect->data = socket;
  if (socket->bind_addr.base.sa_family != AF_UNSPEC) {
    result = uv_tcp_bind(&socket->handle.tcp, &socket->bind_addr.base, 0);
    if (result < 0) {
      rebrick_free(connect);
      rebrick_log_fatal("socket failed:%s\n", uv_strerror(result));
      return REBRICK_ERR_UV + result;
    }
  }

  result = uv_tcp_connect(connect, &socket->handle.tcp, &socket->peer_addr.base, on_connect);
  if (result < 0) {
    rebrick_free(connect);
    rebrick_log_fatal("socket failed:%s\n", uv_strerror(result));
    return REBRICK_ERR_UV + result;
  }

  rebrick_log_info("socket connected to %s port:%s\n", socket->peer_ip, socket->peer_port);
  socket->handle.tcp.data = socket;
  if (socket->start_reading_immediately) {
    uv_stream_t *tmp = cast(&socket->handle.tcp, uv_stream_t *);
    uv_read_start(tmp, on_alloc, on_recv);
    socket->is_reading_started = TRUE;
  }
  return REBRICK_SUCCESS;
}

static int32_t create_server_socket(rebrick_tcpsocket_t *socket, int32_t backlog) {
  char current_time_str[32] = {0};
  unused(current_time_str);
  int32_t result;

  socket->loop = uv_default_loop();
  result = uv_tcp_init(socket->loop, &socket->handle.tcp);
  if (result < 0) {
    // TODO: make it thread safe
    rebrick_log_fatal("socket failed:%s\n", uv_strerror(result));
    return REBRICK_ERR_UV + result;
  }

  result = uv_tcp_bind(&socket->handle.tcp, &socket->bind_addr.base, 0);
  if (result < 0) {
    rebrick_log_fatal("socket failed:%s\n", uv_strerror(result));
    return REBRICK_ERR_UV + result;
  }

  result = uv_listen(cast(&socket->handle.tcp, uv_stream_t *), backlog, on_client_connected);
  if (result < 0) {
    rebrick_log_fatal("socket failed:%s\n", uv_strerror(result));
    return REBRICK_ERR_UV + result;
  }
  rebrick_log_info("socket started at %s port:%s\n", socket->bind_ip, socket->bind_port);
  socket->handle.tcp.data = socket;

  return REBRICK_SUCCESS;
}

int32_t rebrick_tcpsocket_init(rebrick_tcpsocket_t *socket,
                               const rebrick_sockaddr_t *bind_addr,
                               const rebrick_sockaddr_t *peer_addr,
                               int32_t backlog_or_isclient, rebrick_tcpsocket_create_client_t createclient,
                               const rebrick_tcpsocket_callbacks_t *callbacks, int32_t start_reading_immediately) {
  char current_time_str[32] = {0};
  unused(current_time_str);
  int32_t result;
  // burası önemli,callback data
  socket->callback_data = callbacks ? callbacks->callback_data : NULL;
  if (bind_addr)
    memcpy(&socket->bind_addr, bind_addr, sizeof(rebrick_sockaddr_t));
  if (peer_addr)
    memcpy(&socket->peer_addr, peer_addr, sizeof(rebrick_sockaddr_t));

  rebrick_util_addr_to_ip_string(&socket->bind_addr, socket->bind_ip);
  rebrick_util_addr_to_port_string(&socket->bind_addr, socket->bind_port);
  rebrick_util_addr_to_ip_string(&socket->peer_addr, socket->peer_ip);
  rebrick_util_addr_to_port_string(&socket->peer_addr, socket->peer_port);

  socket->on_read = callbacks ? callbacks->on_read : NULL;
  socket->on_write = callbacks ? callbacks->on_write : NULL;
  socket->on_client_connect = callbacks ? callbacks->on_client_connect : NULL;
  socket->on_client_close = callbacks ? callbacks->on_client_close : NULL;
  socket->on_error = callbacks ? callbacks->on_error : NULL;
  socket->on_close = callbacks ? callbacks->on_close : NULL;
  socket->on_connect = callbacks ? callbacks->on_connect : NULL;
  socket->create_client = createclient;
  socket->is_server = backlog_or_isclient;
  socket->start_reading_immediately = start_reading_immediately;

  if (backlog_or_isclient) {
    result = create_server_socket(socket, backlog_or_isclient);
  } else
    result = create_client_socket(socket);
  if (result < 0) {
    if (backlog_or_isclient)
      rebrick_log_fatal("create socket failed bind at %s port:%s\n", socket->bind_ip, socket->bind_port);
    else
      rebrick_log_fatal("create socket failed peer at %s port:%s\n", socket->peer_ip, socket->peer_port);
    return result;
  }

  return REBRICK_SUCCESS;
}

int32_t rebrick_tcpsocket_new(rebrick_tcpsocket_t **socket,
                              const rebrick_sockaddr_t *bind_addr,
                              const rebrick_sockaddr_t *peer_addr,
                              int32_t backlog_or_isclient,
                              const rebrick_tcpsocket_callbacks_t *callbacks) {
  return rebrick_tcpsocket_new2(socket, bind_addr, peer_addr, backlog_or_isclient, callbacks, TRUE);
}

int32_t rebrick_tcpsocket_new2(rebrick_tcpsocket_t **socket,
                               const rebrick_sockaddr_t *bind_addr,
                               const rebrick_sockaddr_t *peer_addr,
                               int32_t backlog_or_isclient,
                               const rebrick_tcpsocket_callbacks_t *callbacks,
                               int32_t start_reading_immediatly) {
  char current_time_str[32] = {0};
  unused(current_time_str);
  int32_t result;
  rebrick_tcpsocket_t *data = new1(rebrick_tcpsocket_t);
  constructor(data, rebrick_tcpsocket_t);

  result = rebrick_tcpsocket_init(data, bind_addr, peer_addr, backlog_or_isclient, create_client, callbacks, start_reading_immediatly);
  if (result < 0) {
    if (backlog_or_isclient)
      rebrick_log_fatal("create socket failed peer at %s port:%s\n", data->peer_ip, data->peer_port);
    else
      rebrick_log_fatal("create socket failed bind at %s port:%s\n", data->bind_ip, data->bind_port);
    rebrick_free(data);
    return result;
  }

  *socket = data;
  return REBRICK_SUCCESS;
}

static void on_close(uv_handle_t *handle) {

  char current_time_str[32] = {0};
  unused(current_time_str);
  if (handle)
    if (handle->data && uv_is_closing(handle)) {
      rebrick_tcpsocket_t *socket = cast_to_tcpsocket(handle->data);
      handle->data = NULL;

      if (socket->on_close) {
        rebrick_log_debug("handle closed\n");
        socket->on_close(cast_to_socket(socket), socket->callback_data);
      }

      rebrick_free(socket);
    }
}

int32_t rebrick_tcpsocket_destroy(rebrick_tcpsocket_t *socket) {
  char current_time_str[32] = {0};
  unused(current_time_str);
  if (socket) {
    // close if server is ready
    uv_tcp_t *tcp = cast(&socket->handle.tcp, uv_tcp_t *);
    uv_handle_t *handle = cast(&socket->handle.tcp, uv_handle_t *);
    if (!uv_is_closing(handle)) {

      rebrick_log_info("resetting connection %s port:%s\n", socket->peer_ip, socket->peer_port);
      // uv_close(handle, on_close);
      uv_tcp_close_reset(tcp, on_close);
    }
  }
  return REBRICK_SUCCESS;
}

int32_t rebrick_tcpsocket_destroy2(rebrick_tcpsocket_t *socket) {
  char current_time_str[32] = {0};
  unused(current_time_str);
  if (socket) {
    // close if server is ready
    uv_handle_t *handle = cast(&socket->handle.tcp, uv_handle_t *);

    if (!uv_is_closing(handle)) {

      rebrick_log_info("closing connection %s port:%s\n", socket->peer_ip, socket->peer_port);
      uv_close(handle, on_close);
    }
  }
  return REBRICK_SUCCESS;
}

int32_t rebrick_tcpsocket_nodelay(rebrick_tcpsocket_t *socket, int enable) {
  if (socket) {
    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;
    result = uv_tcp_nodelay(&socket->handle.tcp, enable);
    if (result < 0) {

      rebrick_log_fatal("socket nodelay failed:%s\n", uv_strerror(result));
      return REBRICK_ERR_UV + result;
    }
  }
  return REBRICK_SUCCESS;
}

int32_t rebrick_tcpsocket_keepalive(rebrick_tcpsocket_t *socket, int enable, int delay) {
  if (socket) {
    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;
    result = uv_tcp_keepalive(&socket->handle.tcp, enable, delay);
    if (result < 0) {

      rebrick_log_fatal("socket keepalive failed:%s\n", uv_strerror(result));
      return REBRICK_ERR_UV + result;
    }
  }
  return REBRICK_SUCCESS;
}
int32_t rebrick_tcpsocket_simultaneous_accepts(rebrick_tcpsocket_t *socket, int enable) {
  if (socket) {
    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;
    result = uv_tcp_simultaneous_accepts(&socket->handle.tcp, enable);
    if (result < 0) {

      rebrick_log_fatal("socket simultaneous accepts failed:%s\n", uv_strerror(result));
      return REBRICK_ERR_UV + result;
    }
  }
  return REBRICK_SUCCESS;
}

int32_t rebrick_tcpsocket_sysctl_write_buffer_size(rebrick_tcpsocket_t *socket, int32_t *value) {
  char current_time_str[32] = {0};
  unused(current_time_str);
  int32_t result;
  if (socket) {
    result = uv_send_buffer_size(cast(&socket->handle.tcp, uv_handle_t *), value);
    if (result < 0) {
      rebrick_log_error("send buffer size failed with error:%d %s\n", result, uv_strerror(result));
      return REBRICK_ERR_UV + result;
    }
  }
  return REBRICK_SUCCESS;
}
int32_t rebrick_tcpsocket_sysctl_read_buffer_size(rebrick_tcpsocket_t *socket, int32_t *value) {
  char current_time_str[32] = {0};
  unused(current_time_str);
  int32_t result;
  if (socket) {
    result = uv_recv_buffer_size(cast(&socket->handle.tcp, uv_handle_t *), value);
    if (result < 0) {
      rebrick_log_error("recv buffer size failed with error:%d %s\n", result, uv_strerror(result));
      return REBRICK_ERR_UV + result;
    }
  }
  return REBRICK_SUCCESS;
}