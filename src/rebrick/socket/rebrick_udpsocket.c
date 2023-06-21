#include "rebrick_udpsocket.h"

static void on_send(uv_udp_send_t *req, int status) {

  rebrick_log_debug("socket on send called and status:%d\n", status);
  rebrick_clean_func_t *clean_func = cast(req->data, rebrick_clean_func_t *);
  void *source = (clean_func && clean_func->anydata.ptr) ? clean_func->anydata.ptr : NULL;

  if (req->handle && !uv_is_closing(cast(req->handle, uv_handle_t *)) && req->handle->data) {

    const rebrick_udpsocket_t *socket = cast_to_udpsocket(req->handle->data);
    if (status >= 0) {
      if (socket->on_write)
        socket->on_write(cast_to_socket(socket), socket->callback_data, source);
    } else {
      if (socket->on_error)
        socket->on_error(cast_to_socket(socket), socket->callback_data, REBRICK_ERR_UV + status);
    }
  }

  if (clean_func) {
    if (clean_func->func) {
      clean_func->func(clean_func->ptr);
    }
    rebrick_free(clean_func);
  }
  rebrick_free(req);
}
int32_t rebrick_udpsocket_write(rebrick_udpsocket_t *socket, const rebrick_sockaddr_t *dstaddr, uint8_t *buffer, size_t len, rebrick_clean_func_t func) {

  char dst_ip[REBRICK_IP_STR_LEN] = {0};
  char dst_port[REBRICK_PORT_STR_LEN] = {0};
  int32_t result;
  if (uv_is_closing(cast(&socket->handle.udp, uv_handle_t *))) {
    return REBRICK_ERR_IO_CLOSING;
  }

  uv_udp_send_t *request = new1(uv_udp_send_t);
  fill_zero(request, sizeof(uv_udp_send_t));
  uv_buf_t buf = uv_buf_init(cast(buffer, char *), len);

  rebrick_clean_func_clone(&func, request->data);

  result = uv_udp_send(request, &socket->handle.udp, &buf, 1, &dstaddr->base, on_send);
  rebrick_util_addr_to_ip_string(dstaddr, dst_ip);
  rebrick_util_addr_to_port_string(dstaddr, dst_port);
  if (result < 0) {

    rebrick_log_info("sending data to server %s port:%s failed\n", dst_ip, dst_port);
    rebrick_free(request->data);
    rebrick_free(request);
    return REBRICK_ERR_UV + result;
  }
  rebrick_log_debug("data sended  len:%zu to server  %s port:%s\n", len, dst_ip, dst_port);
  return REBRICK_SUCCESS;
}

static void on_recv(uv_udp_t *handle, ssize_t nread, const uv_buf_t *rcvbuf, const struct sockaddr *addr, unsigned flags) {

  unused(flags);
  const rebrick_udpsocket_t *socket = cast_to_udpsocket(handle->data);

  if (socket && !uv_is_closing(cast(handle, uv_handle_t *))) {
    if (nread < 0) // error or closed
    {
      if (socket->on_error) {
        rebrick_log_debug("socket error occured %zd\n", nread);
        socket->on_error(cast_to_socket(socket), socket->callback_data, REBRICK_ERR_UV + nread);
      }
    } else if (socket->on_read && nread) {
      rebrick_log_debug("socket receive nread:%zd buflen:%zu\n", nread, rcvbuf->len);
      socket->on_read(cast_to_socket(socket), socket->callback_data, addr, cast(rcvbuf->base, uint8_t *), nread);
    }
  }
  if (rcvbuf->base)
    rebrick_free(rcvbuf->base);
}

static void on_alloc(uv_handle_t *client, size_t suggested_size, uv_buf_t *buf) {
  unused(client);
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

int32_t rebrick_udpsocket_start_reading(rebrick_udpsocket_t *socket) {
  // start reading
  int32_t result;
  if (socket->is_reading_started)
    return REBRICK_SUCCESS;
  result = uv_udp_recv_start(&socket->handle.udp, on_alloc, on_recv);
  if (result)
    return REBRICK_ERR_UV + result;
  socket->is_reading_started = TRUE;
  return REBRICK_SUCCESS;
}

int32_t rebrick_udpsocket_stop_reading(rebrick_udpsocket_t *socket) {
  // stop reading
  int32_t result;
  if (!socket->is_reading_started)
    return REBRICK_SUCCESS;

  result = uv_udp_recv_stop(&socket->handle.udp);
  if (result)
    return REBRICK_ERR_UV + result;
  socket->is_reading_started = FALSE;
  return REBRICK_SUCCESS;
}
int32_t rebrick_udpsocket_write_buffer_size(rebrick_udpsocket_t *socket, size_t *size) {
  *size = uv_udp_get_send_queue_size(&socket->handle.udp);
  return REBRICK_SUCCESS;
}

static int32_t create_socket(rebrick_udpsocket_t *socket) {

  int32_t result;

  socket->loop = uv_default_loop();
  result = uv_udp_init(socket->loop, &socket->handle.udp);
  if (result < 0) {
    rebrick_log_fatal("socket failed:%s\n", uv_strerror(result));
    return REBRICK_ERR_UV + result;
  }

  result = uv_udp_bind(&socket->handle.udp, &socket->bind_addr.base, UV_UDP_REUSEADDR);
  if (result < 0) {
    rebrick_log_fatal("socket failed:%s\n", uv_strerror(result));
    return REBRICK_ERR_UV + result;
  }

  result = uv_udp_recv_start(&socket->handle.udp, on_alloc, on_recv);
  if (result < 0) {
    rebrick_log_fatal("socket failed:%s\n", uv_strerror(result));
    return REBRICK_ERR_UV + result;
  }
  socket->is_reading_started = TRUE;
  rebrick_log_info("socket started at %s port:%s\n", socket->bind_ip, socket->bind_port);
  socket->handle.udp.data = socket;

  return REBRICK_SUCCESS;
}

int32_t rebrick_udpsocket_new(rebrick_udpsocket_t **socket,
                              const rebrick_sockaddr_t *bind_addr,
                              const rebrick_udpsocket_callbacks_t *callbacks) {

  int32_t result;
  rebrick_udpsocket_t *tmp = new1(rebrick_udpsocket_t);
  constructor(tmp, rebrick_udpsocket_t);

  // callback data, copy
  tmp->callback_data = callbacks ? callbacks->callback_data : NULL;
  if (bind_addr)
    memcpy(&tmp->bind_addr.base, bind_addr, sizeof(rebrick_sockaddr_t));
  rebrick_util_addr_to_ip_string(&tmp->bind_addr, tmp->bind_ip);
  rebrick_util_addr_to_port_string(&tmp->bind_addr, tmp->bind_port);

  tmp->on_read = callbacks ? callbacks->on_read : NULL;
  tmp->on_write = callbacks ? callbacks->on_write : NULL;
  tmp->on_error = callbacks ? callbacks->on_error : NULL;
  tmp->on_close = callbacks ? callbacks->on_close : NULL;
  result = create_socket(tmp);
  if (result < 0) {
    rebrick_log_fatal("create socket failed bind at %s port:%s\n", tmp->bind_ip, tmp->bind_port);
    rebrick_free(tmp);
    return result;
  }

  *socket = tmp;
  return REBRICK_SUCCESS;
}

static void on_close(uv_handle_t *handle) {
  if (handle)
    if (handle->data && uv_is_closing(handle)) {
      rebrick_udpsocket_t *socket = cast_to_udpsocket(handle->data);
      if (socket->on_close) {
        rebrick_log_debug("handle closed\n");
        socket->on_close(cast_to_socket(socket), socket->callback_data);
      }
      if (socket)
        rebrick_free(socket);
    }
}

int32_t rebrick_udpsocket_destroy(rebrick_udpsocket_t *socket) {

  if (socket) {
    // close if server is ready

    uv_handle_t *handle = cast(&socket->handle.udp, uv_handle_t *);
    if (!uv_is_closing(handle)) {

      rebrick_log_info("closing connection %s port:%s\n", socket->bind_ip, socket->bind_port);
      uv_close(handle, on_close);
    }
  }
  return REBRICK_SUCCESS;
}

int32_t rebrick_udpsocket_sysctl_write_buffer_size(rebrick_udpsocket_t *socket, int32_t *value) {

  int32_t result;
  if (socket) {
    result = uv_send_buffer_size(cast(&socket->handle.udp, uv_handle_t *), value);
    if (result < 0) {
      rebrick_log_error("send buffer size failed with error:%d %s\n", result, uv_strerror(result));
      return REBRICK_ERR_UV + result;
    }
  }
  return REBRICK_SUCCESS;
}
int32_t rebrick_udpsocket_sysctl_read_buffer_size(rebrick_udpsocket_t *socket, int32_t *value) {

  int32_t result;
  if (socket) {
    result = uv_recv_buffer_size(cast(&socket->handle.udp, uv_handle_t *), value);
    if (result < 0) {
      rebrick_log_error("recv buffer size failed with error:%d %s\n", result, uv_strerror(result));
      return REBRICK_ERR_UV + result;
    }
  }
  return REBRICK_SUCCESS;
}