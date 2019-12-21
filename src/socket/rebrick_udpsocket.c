#include "rebrick_udpsocket.h"

static void on_send(uv_udp_send_t *req, int status)
{

    char current_time_str[32] = {0};

    unused(current_time_str);
    rebrick_log_debug("socket on send called and status:%d\n", status);

    rebrick_clean_func_t *clean_func = cast(req->data, rebrick_clean_func_t *);
    void *source = (clean_func && clean_func->anydata.ptr) ? clean_func->anydata.ptr : NULL;

    if (req->handle && req->handle->data)
    {

        const rebrick_udpsocket_t *socket = cast_to_udpsocket(req->handle->data);
        if (status >= 0)
        {
            if (socket->on_data_sended)
                socket->on_data_sended(cast_to_socket(socket), socket->callback_data, source);
        }
        else
        {
            if (socket->on_error_occured)
                socket->on_error_occured(cast_to_socket(socket), socket->callback_data, REBRICK_ERR_UV + status);
        }
    }

    if (clean_func)
    {
        if (clean_func->func)
        {
            clean_func->func(clean_func->ptr);
        }
        free(clean_func);
    }
    free(req);
}
int32_t rebrick_udpsocket_send(rebrick_udpsocket_t *socket, rebrick_sockaddr_t *dstaddr, uint8_t *buffer, size_t len, rebrick_clean_func_t func)
{

    char current_time_str[32] = {0};
    unused(current_time_str);
    char dst_ip[REBRICK_IP_STR_LEN];
    char dst_port[REBRICK_PORT_STR_LEN];
    int32_t result;

    uv_udp_send_t *request = new (uv_udp_send_t);
    fill_zero(request, sizeof(uv_udp_send_t));
    uv_buf_t buf = uv_buf_init(cast(buffer, char *), len);

    rebrick_clean_func_clone(&func, request->data);

    result = uv_udp_send(request, &socket->handle.udp, &buf, 1, &dstaddr->base, on_send);
    rebrick_util_addr_to_ip_string(dstaddr, dst_ip);
    rebrick_util_addr_to_port_string(dstaddr, dst_port);
    if (result < 0)
    {

        rebrick_log_info("sending data to server %s port:%s failed\n", dst_ip, dst_port);
        return REBRICK_ERR_UV + result;
    }
    rebrick_log_debug("data sended  len:%zu to server  %s port:%s\n", len, dst_ip, dst_port);
    return REBRICK_SUCCESS;
}

static void on_recv(uv_udp_t *handle, ssize_t nread, const uv_buf_t *rcvbuf, const struct sockaddr *addr, unsigned flags)
{

    char current_time_str[32] = {0};
    unused(current_time_str);
    unused(flags);
    const rebrick_udpsocket_t *socket = cast_to_udpsocket(handle->data);

    rebrick_log_debug("socket receive nread:%zd buflen:%zu\n", nread, rcvbuf->len);

    if (socket)
    {
        if (nread <= 0) //error or closed
        {
            if (socket->on_error_occured)
                socket->on_error_occured(cast_to_socket(socket), socket->callback_data, REBRICK_ERR_IO_CLOSED);
        }
        else if (socket->on_data_received)
        {
            socket->on_data_received(cast_to_socket(socket), socket->callback_data, addr, cast(rcvbuf->base, uint8_t *), nread);
        }
    }

    free(rcvbuf->base);
}

static void on_alloc(uv_handle_t *client, size_t suggested_size, uv_buf_t *buf)
{
    unused(client);
    char current_time_str[32] = {0};
    if (suggested_size <= 0)
    {
        rebrick_log_info("socket suggested_size is 0 from \n");
        return;
    }

    buf->base = malloc(suggested_size);
    if_is_null_then_die(buf->base, "malloc problem\n");

    buf->len = suggested_size;
    fill_zero(buf->base, buf->len);
    rebrick_log_debug("malloc socket:%lu %p\n", buf->len, buf->base);
}

static int32_t create_socket(rebrick_udpsocket_t *socket)
{
    char current_time_str[32] = {0};

    int32_t result;

    socket->loop = uv_default_loop();
    result = uv_udp_init(socket->loop, &socket->handle.udp);
    if (result < 0)
    {
        // TODO: burası multi thread değil
        rebrick_log_fatal("socket failed:%s\n", uv_strerror(result));
        return REBRICK_ERR_UV + result;
    }

    result = uv_udp_bind(&socket->handle.udp, &socket->bind_addr.base, UV_UDP_REUSEADDR);
    if (result < 0)
    {
        rebrick_log_fatal("socket failed:%s\n", uv_strerror(result));
        return REBRICK_ERR_UV + result;
    }

    result = uv_udp_recv_start(&socket->handle.udp, on_alloc, on_recv);
    if (result < 0)
    {
        rebrick_log_fatal("socket failed:%s\n", uv_strerror(result));
        return REBRICK_ERR_UV + result;
    }
    rebrick_log_info("socket started at %s port:%s\n", socket->bind_ip, socket->bind_port);
    socket->handle.udp.data = socket;

    return REBRICK_SUCCESS;
}

int32_t rebrick_udpsocket_new(rebrick_udpsocket_t **socket,
                              rebrick_sockaddr_t bind_addr,
                              const rebrick_udpsocket_callbacks_t *callbacks)
{

    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;
    rebrick_udpsocket_t *tmp = new (rebrick_udpsocket_t);
    constructor(tmp, rebrick_udpsocket_t);

    //burası önemli,callback data
    tmp->callback_data = callbacks ? callbacks->callback_data : NULL;

    tmp->bind_addr = bind_addr;
    rebrick_util_addr_to_ip_string(&tmp->bind_addr, tmp->bind_ip);
    rebrick_util_addr_to_port_string(&tmp->bind_addr, tmp->bind_port),

    tmp->on_data_received = callbacks ? callbacks->on_data_received : NULL;
    tmp->on_data_sended = callbacks ? callbacks->on_data_sended : NULL;
    tmp->on_error_occured = callbacks ? callbacks->on_error_occured : NULL;

    result = create_socket(tmp);
    if (result < 0)
    {
        rebrick_log_fatal("create socket failed bind at %s port:%s\n", tmp->bind_ip, tmp->bind_port);

        free(tmp);
        return result;
    }

    *socket = tmp;
    return REBRICK_SUCCESS;
}

static void on_close(uv_handle_t *handle)
{
    if (handle)
        if (handle->data)
        {
            rebrick_udpsocket_t *socket = cast_to_udpsocket(handle->data);
            if (socket)
                free(socket);
        }
}

int32_t rebrick_udpsocket_destroy(rebrick_udpsocket_t *socket)
{
    char current_time_str[32] = {0};
    unused(current_time_str);
    if (socket)
    {
        //close if server is ready

        uv_handle_t *handle = cast(&socket->handle.udp, uv_handle_t *);
        if (!uv_is_closing(handle))
        {

            rebrick_log_info("closing connection %s port:%s\n", socket->bind_ip, socket->bind_port);
            uv_close(handle, on_close);
        }
    }
    return REBRICK_SUCCESS;
}


int32_t rebrick_udpsocket_send_buffer_size(rebrick_udpsocket_t *socket,int32_t *value){
  char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;
    if (socket){
        result=uv_send_buffer_size(cast(&socket->handle.udp,uv_handle_t*),value);
        if(result<0){
            rebrick_log_error("send buffer size failed with error:%d %s\n",result,uv_strerror(result));
            return REBRICK_ERR_UV+result;
        }

    }
    return REBRICK_SUCCESS;
}
int32_t rebrick_udpsocket_recv_buffer_size(rebrick_udpsocket_t *socket,int32_t *value){
    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;
    if (socket){
        result=uv_recv_buffer_size(cast(&socket->handle.udp,uv_handle_t*),value);
        if(result<0){
            rebrick_log_error("recv buffer size failed with error:%d %s\n",result,uv_strerror(result));
            return REBRICK_ERR_UV+result;
        }

    }
    return REBRICK_SUCCESS;
}