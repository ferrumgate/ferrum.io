#include "rebrick_async_tcpsocket.h"

static void on_close(uv_handle_t *handle);

static void on_send(uv_write_t *req, int status)
{
    // TODO: status a göre işlem yapılmalı

    char current_time_str[32] = {0};

    unused(current_time_str);
    rebrick_log_debug("socket on send called and status:%d\n", status);

    if (req->handle)
        if (req->handle->data)
        {
            const rebrick_async_tcpsocket_t *socket = cast(req->handle->data, rebrick_async_tcpsocket_t *);

            if (socket->after_data_sended)
                socket->after_data_sended(cast_to_base_socket(socket), socket->callback_data, req->data, status);
        }
    free(req);
}

int32_t rebrick_async_tcpsocket_send(rebrick_async_tcpsocket_t *socket, char *buffer, size_t len, void *aftersend_data)
{

    char current_time_str[32] = {0};

    int32_t result;
    if(uv_is_closing(cast(&socket->handle.tcp,uv_handle_t*))){
        return REBRICK_ERR_IO_CLOSED;
    }

    uv_write_t *request = new (uv_write_t);
    if_is_null_then_die(request, "malloc problem\n");
    fill_zero(request, sizeof(uv_write_t));
    uv_buf_t buf = uv_buf_init(buffer, len);

    request->data = aftersend_data;

    result = uv_write(request, cast(&socket->handle.tcp, uv_stream_t *), &buf, 1, on_send);
    if (result < 0)
    {

        rebrick_log_info("sending data to  %s port:%s failed: %s\n", socket->bind_ip, socket->bind_port,uv_strerror(result));
        return REBRICK_ERR_UV + result;
    }
    rebrick_log_debug("data sended  len:%zu to   %s port:%s\n", len, socket->bind_ip, socket->bind_port);
    return REBRICK_SUCCESS;
}

static void on_recv(uv_stream_t *handle, ssize_t nread, const uv_buf_t *rcvbuf)
{

    char current_time_str[32] = {0};
    unused(current_time_str);

    const rebrick_async_tcpsocket_t *socket = cast(handle->data, rebrick_async_tcpsocket_t *);

    rebrick_log_debug("socket receive nread:%zd buflen:%zu\n", nread, rcvbuf->len);
   /*  if (nread <= 0) //burası silinirse,
    {

        rebrick_log_debug("nread is %zd <=0  from %s port %s\n", nread, socket->bind_ip, socket->bind_port);
        free(rcvbuf->base);
        uv_handle_t *tmp = cast(&socket->handle.tcp, uv_handle_t *);
        uv_close(tmp, on_close);
        return;
    } */


    if (socket->after_data_received)
    {
        if(nread<0)
        nread+=REBRICK_ERR_UV;
        socket->after_data_received(cast_to_base_socket(socket),socket->callback_data, NULL, rcvbuf->base, nread);
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

    if (status == -1)
    {
        rebrick_log_debug("error on_new_connection\n");
       // return;
    }

    rebrick_async_tcpsocket_t *serversocket = cast(connection->data, rebrick_async_tcpsocket_t *);
    if(serversocket)
    if (serversocket->after_connection_accepted)
    {
        serversocket->after_connection_accepted(cast_to_base_socket(serversocket),serversocket->callback_data, NULL, serversocket,status);
    }

    free(connection);
}


static rebrick_async_tcpsocket_t * create_client(){
    char current_time_str[32] = {0};
    rebrick_async_tcpsocket_t *client=new(rebrick_async_tcpsocket_t);
    constructor(client,rebrick_async_tcpsocket_t);
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
    int32_t temp=0;
    if(!server){
        rebrick_log_fatal("server parameter is null\n");
        return;
    }



    uv_tcp_t *tcp = cast(server, uv_tcp_t *);
    rebrick_async_tcpsocket_t *serversocket = cast(tcp->data, rebrick_async_tcpsocket_t *);

     if (status == -1)
    {
        rebrick_log_debug("error on_new_connection\n");
        if(server && serversocket->after_connection_accepted)
        serversocket->after_connection_accepted(cast_to_base_socket(serversocket),serversocket->callback_data,NULL,NULL,status);
        return;
    }

    //burayı override etmeyi başarsak//ssl için yol açmış oluruz

    rebrick_async_tcpsocket_t *client = serversocket->create_client();

    uv_tcp_init(uv_default_loop(), &client->handle.tcp);

    result = uv_accept(server, cast(&client->handle.tcp, uv_stream_t *));
    if (result < 0)
    {
        // TODO: make it threadsafe
        rebrick_log_fatal("accept error uverror:%d %s\n", result, uv_strerror(result));

        free(client);
        //TODO burada extra bir şey lazımmı
        return;
    }
    temp=sizeof(struct sockaddr_storage);
    result=uv_tcp_getpeername(&client->handle.tcp, &client->bind_addr.base, &temp);



    rebrick_util_addr_to_ip_string(&client->bind_addr, client->bind_ip);
    rebrick_util_addr_to_port_string(&client->bind_addr, client->bind_port);
    rebrick_log_debug("connected client from %s:%s\n", client->bind_ip, client->bind_port);

    client->handle.tcp.data = client;
    client->after_connection_closed = serversocket->after_connection_closed;
    client->after_data_received = serversocket->after_data_received;
    client->after_data_sended = serversocket->after_data_sended;
    client->callback_data = serversocket->callback_data;
    client->parent_socket = serversocket;

    client->loop=serversocket->loop;

    //rebrick_async_tcpsocket_t **head=&serversocket->clients;

    DL_APPEND(serversocket->clients, client);



    //start reading client
    uv_stream_t *tmp = cast(&client->handle.tcp, uv_stream_t *);
    uv_read_start(tmp, on_alloc, on_recv);

    if (serversocket->after_connection_accepted)
    {
        serversocket->after_connection_accepted(cast_to_base_socket(serversocket),client->callback_data, &client->bind_addr.base, client,status);
    }
    //burada kaldım.
}

static int32_t create_client_socket(rebrick_async_tcpsocket_t *socket)
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
    uv_connect_t *connect = new(uv_connect_t);
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

static int32_t create_server_socket(rebrick_async_tcpsocket_t *socket, int32_t backlog)
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

int32_t rebrick_async_tcpsocket_init(rebrick_async_tcpsocket_t *socket, rebrick_sockaddr_t addr, void *callback_data,
                                     rebrick_after_connection_accepted_callback_t after_connection_accepted,
                                     rebrick_after_connection_closed_callback_t after_connection_closed,
                                     rebrick_after_data_received_callback_t after_data_received,
                                     rebrick_after_data_sended_callback_t after_data_sended,
                                      int32_t backlog_or_isclient,rebrick_async_tcpsocket_create_client_t createclient)
{
     char current_time_str[32] = {0};
    int32_t result;
    //burası önemli,callback data
    socket->callback_data = callback_data;

    socket->bind_addr = addr;
    rebrick_util_addr_to_ip_string(&socket->bind_addr, socket->bind_ip);
    rebrick_util_addr_to_port_string(&socket->bind_addr, socket->bind_port),

    socket->after_data_received = after_data_received;
    socket->after_data_sended = after_data_sended;
    socket->after_connection_accepted = after_connection_accepted;
    socket->after_connection_closed = after_connection_closed;
    socket->create_client=createclient;
    if (backlog_or_isclient){
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

int32_t rebrick_async_tcpsocket_new(rebrick_async_tcpsocket_t **socket,
                                    rebrick_sockaddr_t bind_addr,
                                    void *callback_data,
                                    rebrick_after_connection_accepted_callback_t after_connection_accepted,
                                    rebrick_after_connection_closed_callback_t after_connection_closed,
                                    rebrick_after_data_received_callback_t after_data_received,
                                    rebrick_after_data_sended_callback_t after_data_sended, int32_t backlog_or_isclient)
{
    char current_time_str[32] = {0};
    int32_t result;
    rebrick_async_tcpsocket_t *data = new (rebrick_async_tcpsocket_t);
    constructor(data, rebrick_async_tcpsocket_t);

    result=rebrick_async_tcpsocket_init(data,bind_addr,callback_data,after_connection_accepted,after_connection_closed,after_data_received,after_data_sended,
    backlog_or_isclient,create_client);
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
            rebrick_async_tcpsocket_t *socket = cast(handle->data, rebrick_async_tcpsocket_t *);
            handle->data=NULL;

            if (socket->after_connection_closed)
            {
                rebrick_log_debug("handle closed\n");
                socket->after_connection_closed(cast_to_base_socket(socket),socket->callback_data);
            }
            //server is closing
            if(!socket->parent_socket){

                struct rebrick_async_tcpsocket *el, *tmp;
                DL_FOREACH_SAFE(socket->clients, el,tmp)
                {
                        DL_DELETE(socket->clients, el);
                        el->parent_socket=NULL;
                        rebrick_async_tcpsocket_destroy(el);

                }
            }else{


                if(socket->parent_socket->clients)
                DL_DELETE(socket->parent_socket->clients,socket);
            }

            free(socket);



        }

}

int32_t rebrick_async_tcpsocket_destroy(rebrick_async_tcpsocket_t *socket)
{
    char current_time_str[32] = {0};
    unused(current_time_str);
    if (socket)
    {
        //close if server is ready
        uv_handle_t *handle = cast(&socket->handle.tcp, uv_handle_t *);

        if (!uv_is_closing(handle))
        {
            //server is closing
           // if (!socket->parent_socket)
            //{

                //server socket is closing
               /*  struct rebrick_async_tcpsocket *el, *tmp;
                DL_FOREACH_SAFE(socket->clients, el, tmp)
                {
                        DL_DELETE(socket->clients, el);
                        rebrick_async_tcpsocket_destroy(el);

                } */
            //}
            rebrick_log_info("closing connection %s port:%s\n", socket->bind_ip, socket->bind_port);
            uv_close(handle, on_close);
        }
    }
    return REBRICK_SUCCESS;
}