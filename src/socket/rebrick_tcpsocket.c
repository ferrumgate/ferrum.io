#include "rebrick_tcpsocket.h"

static void on_close(uv_handle_t *handle);

static void on_send(uv_write_t *req, int status)
{
    char current_time_str[32] = {0};
    unused(current_time_str);
    rebrick_log_debug("socket on send called and status:%d\n", status);

    rebrick_clean_func_t *clean_func = cast(req->data, rebrick_clean_func_t *);
    void *source = clean_func ? clean_func->anydata.ptr : NULL;
    if (req->handle && req->handle->data)

    {
        const rebrick_tcpsocket_t *socket = cast(req->handle->data, rebrick_tcpsocket_t *);

        if (status < 0)
        {
            if (socket->on_error_occured)
                socket->on_error_occured(cast_to_base_socket(socket), socket->callback_data, REBRICK_ERR_UV + status);
        }
        else if (socket->on_data_sended)
            socket->on_data_sended(cast_to_base_socket(socket), socket->callback_data, source);
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

int32_t rebrick_tcpsocket_send(rebrick_tcpsocket_t *socket, char *buffer, size_t len, rebrick_clean_func_t cleanfunc)
{

    char current_time_str[32] = {0};

    int32_t result;
    if (uv_is_closing(cast(&socket->handle.tcp, uv_handle_t *)))
    {
        return REBRICK_ERR_IO_CLOSED;
    }

    uv_write_t *request = new (uv_write_t);
    if_is_null_then_die(request, "malloc problem\n");
    fill_zero(request, sizeof(uv_write_t));
    uv_buf_t buf = uv_buf_init(buffer, len);

    rebrick_clean_func_clone(&cleanfunc, request->data);

    result = uv_write(request, cast(&socket->handle.tcp, uv_stream_t *), &buf, 1, on_send);
    if (result < 0)
    {

        rebrick_log_info("sending data to  %s port:%s failed: %s\n", socket->bind_ip, socket->bind_port, uv_strerror(result));
        return REBRICK_ERR_UV + result;
    }
    rebrick_log_debug("data sended  len:%zu to   %s port:%s\n", len, socket->bind_ip, socket->bind_port);
    return REBRICK_SUCCESS;
}

static void on_recv(uv_stream_t *handle, ssize_t nread, const uv_buf_t *rcvbuf)
{

    char current_time_str[32] = {0};
    unused(current_time_str);

    const rebrick_tcpsocket_t *socket = cast(handle->data, rebrick_tcpsocket_t *);

    rebrick_log_debug("socket receive nread:%zd buflen:%zu\n", nread, rcvbuf->len);

    if (nread <= 0)
    {
        if (socket->on_error_occured)
            socket->on_error_occured(cast_to_base_socket(socket), NULL, REBRICK_ERR_IO_CLOSED);
    }
    else if (socket->on_data_received)
    {

        socket->on_data_received(cast_to_base_socket(socket), socket->callback_data, NULL, rcvbuf->base, nread);
    }

    free(rcvbuf->base);
}

static void on_alloc(uv_handle_t *client, size_t suggested_size, uv_buf_t *buf)
{
    unused(client);
    char current_time_str[32] = {0};
    unused(current_time_str);
    if (suggested_size <= 0)
    {
        rebrick_log_info("socket suggested_size is 0 from \n");
        return;
    }

    buf->base = malloc(suggested_size);
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

static void on_connect(uv_connect_t *connection, int status)
{
    char current_time_str[32] = {0};
    unused(current_time_str);


    rebrick_tcpsocket_t *serversocket = cast(connection->data, rebrick_tcpsocket_t *);

    if (serversocket)
    {
        if (status < 0)
        {
            if (serversocket->on_error_occured)
                serversocket->on_error_occured(cast_to_base_socket(serversocket), serversocket->callback_data, REBRICK_ERR_UV + status);
        }
        else if (serversocket->on_connection_accepted)
        {
            serversocket->on_connection_accepted(cast_to_base_socket(serversocket), serversocket->callback_data, NULL, serversocket);
        }
    }

    free(connection);
}

static rebrick_tcpsocket_t *create_client()
{
    char current_time_str[32] = {0};
    rebrick_tcpsocket_t *client = new (rebrick_tcpsocket_t);
    constructor(client, rebrick_tcpsocket_t);
    return client;
}
/**
 * @brief on new client connection received
 *
 * @param server
 * @param status
 */
static void on_connection(uv_stream_t *server, int status)
{
    char current_time_str[32] = {0};
    unused(current_time_str);

    int32_t result;
    int32_t temp = 0;
    if (!server)
    {
        rebrick_log_fatal("server parameter is null\n");
        return;
    }

    uv_tcp_t *tcp = cast(server, uv_tcp_t *);
    rebrick_tcpsocket_t *serversocket = cast(tcp->data, rebrick_tcpsocket_t *);

    if (status < 0)
    {
        rebrick_log_debug("error on_new_connection\n");
        if (server && serversocket->on_error_occured)
            serversocket->on_error_occured(cast_to_base_socket(serversocket), serversocket->callback_data,REBRICK_ERR_UV+ status);
        return;
    }

    //burayı override etmeyi başarsak//ssl için yol açmış oluruz

    rebrick_tcpsocket_t *client = serversocket->create_client();

    uv_tcp_init(uv_default_loop(), &client->handle.tcp);

    result = uv_accept(server, cast(&client->handle.tcp, uv_stream_t *));
    if (result < 0)
    {
        // TODO: make it threadsafe
        rebrick_log_fatal("accept error uverror:%d %s\n", result, uv_strerror(result));
        //burada client direk free edilebilmeli
        //başka bir şey olmadan
        //@see rebrick_tcpsocket.h
        free(client);

        return;
    }
    temp = sizeof(struct sockaddr_storage);
    result = uv_tcp_getpeername(&client->handle.tcp, &client->bind_addr.base, &temp);

    rebrick_util_addr_to_ip_string(&client->bind_addr, client->bind_ip);
    rebrick_util_addr_to_port_string(&client->bind_addr, client->bind_port);
    rebrick_log_debug("connected client from %s:%s\n", client->bind_ip, client->bind_port);

    client->handle.tcp.data = client;
    client->on_connection_closed = serversocket->on_connection_closed;
    client->on_data_received = serversocket->on_data_received;
    client->on_data_sended = serversocket->on_data_sended;
    client->callback_data = serversocket->callback_data;
    client->parent_socket = serversocket;

    client->loop = serversocket->loop;



    DL_APPEND(serversocket->clients, client);

    //start reading client
    uv_stream_t *tmp = cast(&client->handle.tcp, uv_stream_t *);
    uv_read_start(tmp, on_alloc, on_recv);

    if (serversocket->on_connection_accepted)
    {
        serversocket->on_connection_accepted(cast_to_base_socket(serversocket), client->callback_data, &client->bind_addr.base, client);
    }

}

static int32_t create_client_socket(rebrick_tcpsocket_t *socket)
{
    char current_time_str[32] = {0};
    int32_t result;

    socket->loop = uv_default_loop();
    result = uv_tcp_init(socket->loop, &socket->handle.tcp);
    if (result < 0)
    {
        // TODO: make it thread safe
        rebrick_log_fatal("socket failed:%s\n", uv_strerror(result));
        return REBRICK_ERR_UV + result;
    }
    uv_tcp_keepalive(&socket->handle.tcp, 1, 60);
    uv_connect_t *connect = new (uv_connect_t);
    if_is_null_then_die(connect, "malloc problem\n");
    connect->data = socket;
    result = uv_tcp_connect(connect, &socket->handle.tcp, &socket->bind_addr.base, on_connect);
    if (result < 0)
    {
        rebrick_log_fatal("socket failed:%s\n", uv_strerror(result));
        return REBRICK_ERR_UV + result;
    }

    rebrick_log_info("socket connected to %s port:%s\n", socket->bind_ip, socket->bind_port);
    socket->handle.tcp.data = socket;
    uv_stream_t *tmp = cast(&socket->handle.tcp, uv_stream_t *);
    uv_read_start(tmp, on_alloc, on_recv);
    return REBRICK_SUCCESS;
}

static int32_t create_server_socket(rebrick_tcpsocket_t *socket, int32_t backlog)
{
    char current_time_str[32] = {0};
    int32_t result;

    socket->loop = uv_default_loop();
    result = uv_tcp_init(socket->loop, &socket->handle.tcp);
    if (result < 0)
    {
        // TODO: make it thread safe
        rebrick_log_fatal("socket failed:%s\n", uv_strerror(result));
        return REBRICK_ERR_UV + result;
    }

    result = uv_tcp_bind(&socket->handle.tcp, &socket->bind_addr.base, 0);
    if (result < 0)
    {
        rebrick_log_fatal("socket failed:%s\n", uv_strerror(result));
        return REBRICK_ERR_UV + result;
    }

    result = uv_listen(cast(&socket->handle.tcp, uv_stream_t *), backlog, on_connection);
    if (result < 0)
    {
        rebrick_log_fatal("socket failed:%s\n", uv_strerror(result));
        return REBRICK_ERR_UV + result;
    }
    rebrick_log_info("socket started at %s port:%s\n", socket->bind_ip, socket->bind_port);
    socket->handle.tcp.data = socket;

    return REBRICK_SUCCESS;
}

int32_t rebrick_tcpsocket_init(rebrick_tcpsocket_t *socket, rebrick_sockaddr_t addr, void *callback_data,
                                     rebrick_on_connection_accepted_callback_t on_connection_accepted,
                                     rebrick_on_connection_closed_callback_t on_connection_closed,
                                     rebrick_on_data_received_callback_t on_data_received,
                                     rebrick_on_data_sended_callback_t on_data_sended,
                                     rebrick_on_error_occured_callback_t on_error_occured,
                                     int32_t backlog_or_isclient, rebrick_tcpsocket_create_client_t createclient)
{
    char current_time_str[32] = {0};
    int32_t result;
    //burası önemli,callback data
    socket->callback_data = callback_data;

    socket->bind_addr = addr;
    rebrick_util_addr_to_ip_string(&socket->bind_addr, socket->bind_ip);
    rebrick_util_addr_to_port_string(&socket->bind_addr, socket->bind_port),

        socket->on_data_received = on_data_received;
    socket->on_data_sended = on_data_sended;
    socket->on_connection_accepted = on_connection_accepted;
    socket->on_connection_closed = on_connection_closed;
    socket->on_error_occured=on_error_occured;
    socket->create_client = createclient;

    if (backlog_or_isclient)
    {
        result = create_server_socket(socket, backlog_or_isclient);
    }
    else
        result = create_client_socket(socket);
    if (result < 0)
    {
        rebrick_log_fatal("create socket failed bind at %s port:%s\n", socket->bind_ip, socket->bind_port);
        return result;
    }

    return REBRICK_SUCCESS;
}

int32_t rebrick_tcpsocket_new(rebrick_tcpsocket_t **socket,
                                    rebrick_sockaddr_t bind_addr,
                                    void *callback_data,
                                    rebrick_on_connection_accepted_callback_t on_connection_accepted,
                                    rebrick_on_connection_closed_callback_t on_connection_closed,
                                    rebrick_on_data_received_callback_t on_data_received,
                                    rebrick_on_data_sended_callback_t on_data_sended,
                                    rebrick_on_error_occured_callback_t on_error_occured,
                                     int32_t backlog_or_isclient)
{
    char current_time_str[32] = {0};
    int32_t result;
    rebrick_tcpsocket_t *data = new (rebrick_tcpsocket_t);
    constructor(data, rebrick_tcpsocket_t);

    result = rebrick_tcpsocket_init(data, bind_addr, callback_data, on_connection_accepted, on_connection_closed, on_data_received, on_data_sended,on_error_occured,
                                          backlog_or_isclient, create_client);
    if (result < 0)
    {
        rebrick_log_fatal("create socket failed bind at %s port:%s\n", data->bind_ip, data->bind_port);
        free(data);

        return result;
    }

    *socket = data;
    return REBRICK_SUCCESS;
}

static void on_close(uv_handle_t *handle)
{

    char current_time_str[32] = {0};
    unused(current_time_str);
    if (handle)
        if (handle->data && uv_is_closing(handle))
        {
            rebrick_tcpsocket_t *socket = cast(handle->data, rebrick_tcpsocket_t *);
            handle->data = NULL;

            if (socket->on_connection_closed)
            {
                rebrick_log_debug("handle closed\n");
                socket->on_connection_closed(cast_to_base_socket(socket), socket->callback_data);
            }
            //server is closing
            if (!socket->parent_socket)
            {

                struct rebrick_tcpsocket *el, *tmp;
                DL_FOREACH_SAFE(socket->clients, el, tmp)
                {
                    DL_DELETE(socket->clients, el);
                    el->parent_socket = NULL;
                    rebrick_tcpsocket_destroy(el);
                }
            }
            else
            {

                if (socket->parent_socket->clients)
                    DL_DELETE(socket->parent_socket->clients, socket);
            }

            free(socket);
        }
}

int32_t rebrick_tcpsocket_destroy(rebrick_tcpsocket_t *socket)
{
    char current_time_str[32] = {0};
    unused(current_time_str);
    if (socket)
    {
        //close if server is ready
        uv_handle_t *handle = cast(&socket->handle.tcp, uv_handle_t *);

        if (!uv_is_closing(handle))
        {

            rebrick_log_info("closing connection %s port:%s\n", socket->bind_ip, socket->bind_port);
            uv_close(handle, on_close);
        }
    }
    return REBRICK_SUCCESS;
}