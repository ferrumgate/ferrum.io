#include "rebrick_async_tcpsocket.h"

static void on_close(uv_handle_t *handle);



private
typedef struct rebrick_async_tcpsocket_data
{
    base_class();
    char bind_ip[REBRICK_IP_STR_LEN];
    char bind_port[REBRICK_PORT_STR_LEN];

    uv_loop_t *loop;
    uv_tcp_t handle;
    rebrick_sockaddr_t bind_addr;
    // for clients
    rebrick_after_data_received_callback_t after_data_received;
    //for clients
    rebrick_after_data_sended_callback_t after_data_sended;
    //for servers
    rebrick_after_connection_accepted_callback_t after_connection_accepted;
    //for server
    rebrick_after_connection_closed_callback_t after_connection_closed;


    /**
     * @brief customer user data for every callback
     *
     */
    void *callback_data;

    struct rebrick_async_tcpsocket_data *clients;

    struct rebrick_async_tcpsocket_data *prev;
    struct rebrick_async_tcpsocket_data *next;
    // server socket
    struct rebrick_async_tcpsocket *parent;


} rebrick_async_tcpsocket_data_t;

static void on_send(uv_write_t *req, int status)
{
    // TODO: status a göre işlem yapılmalı

    char current_time_str[32] = {0};

    unused(current_time_str);
    rebrick_log_debug("socket on send called and status:%d\n", status);
    if (req->data)
    {
        char *data = cast(req->data, char *);
        if (data)
        {

            free(data);
        }
    }
    if (req->handle)
        if (req->handle->data)
        {
            const rebrick_async_tcpsocket_t *socketwrapper=cast(req->handle->data,rebrick_async_tcpsocket_t*);
            const rebrick_async_tcpsocket_data_t *socket = cast(socketwrapper->data, rebrick_async_tcpsocket_data_t *);
            if (socket->after_data_sended)
                socket->after_data_sended(socket->callback_data, status);
        }
    free(req);
}

int32_t rebrick_async_tcpsocket_send(rebrick_async_tcpsocket_t *socket, rebrick_sockaddr_t *dstaddr, char *buffer, size_t len)
{

    char current_time_str[32] = {0};
    char dst_ip[REBRICK_IP_STR_LEN];
    char dst_port[REBRICK_PORT_STR_LEN];
    int32_t result;
    rebrick_async_tcpsocket_data_t *data = cast(socket->data, rebrick_async_tcpsocket_data_t *);
    uv_write_t *request = new (uv_write_t);
    if_is_null_then_die(request,"malloc problem\n");
    fill_zero(request, sizeof(uv_write_t));
    uv_buf_t buf = uv_buf_init(buffer, len);

    request->data = buf.base;
    result = uv_write(request, cast(&data->handle,uv_stream_t*), &buf, 1, on_send);
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


static void on_recv(uv_stream_t *handle, ssize_t nread, const uv_buf_t *rcvbuf)
{

    char current_time_str[32] = {0};
    unused(current_time_str);

    const rebrick_async_tcpsocket_t *handler = cast(handle->data,rebrick_async_tcpsocket_t*);
    const rebrick_async_tcpsocket_data_t *socket = cast(handler->data, rebrick_async_tcpsocket_data_t *);

    rebrick_log_debug("socket receive nread:%zd buflen:%zu\n", nread, rcvbuf->len);
    if (nread <= 0) //burası silinirse,
    {

        rebrick_log_debug("nread is %zd <=0  from %s port %s\n",nread, socket->bind_ip, socket->bind_port);
        free(rcvbuf->base);
        uv_handle_t* tmp=cast(&socket->handle,uv_handle_t*);
        uv_close(tmp,on_close);
        return;
    }


        if (socket->after_data_received && nread > 0)
        {
            //nread ssize_t olmasına karşın parametre olarak geçildi
            //neticed eğer nread<0 zaten buraya gelmiyor
            socket->after_data_received(socket->callback_data,NULL, rcvbuf->base, nread);
        }

    free(rcvbuf->base);
}

static void on_alloc(uv_handle_t *client, size_t suggested_size,uv_buf_t *buf)
{
    unused(client);
    char current_time_str[32] = {0};
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
 * @brief on new client connection received
 *
 * @param server
 * @param status
 */
static void on_connection(uv_stream_t *server, int status)
{
    char current_time_str[32] = {0};
    unused(current_time_str);
    char ip_buffer[REBRICK_IP_STR_LEN] = {'\0'};
    int32_t result;
    int32_t temp;
    if (status == -1)
    {
        rebrick_log_debug("error on_new_connection\n");
        return;
    }



    uv_tcp_t *tcp = cast(server, uv_tcp_t *);
    rebrick_async_tcpsocket_t *serversockethandle = cast(tcp->data, rebrick_async_tcpsocket_t *);
    rebrick_async_tcpsocket_data_t *serversocketdata = cast(serversockethandle->data, rebrick_async_tcpsocket_data_t *);

    uv_tcp_t tcpclient;
    fill_zero(&tcpclient, sizeof(uv_tcp_t));

    result = uv_accept(server,cast(&tcpclient,uv_stream_t*));
    if (result < 0)
    {
        // TODO: make it threadsafe
        rebrick_log_fatal("accept error uverror:%d %s\n", result, uv_strerror(result));
        //TODO burada extra bir şey lazımmı
        return;
    }

    rebrick_async_tcpsocket_t *client= new (rebrick_async_tcpsocket_t);
    constructor(client,rebrick_async_tcpsocket_t,"rebrick_tcpclient_data_t");

    rebrick_async_tcpsocket_data_t *clientdata=new(rebrick_async_tcpsocket_data_t);
    constructor(clientdata,rebrick_async_tcpsocket_data_t,"rebrick_async_tcpsocket_data_t");
    //clone current client handle
    memcpy(&clientdata->handle,&tcpclient,sizeof(uv_tcp_t));
    //important
    client->data=clientdata;


    uv_tcp_getsockname(&clientdata->handle, &clientdata->bind_addr.base, &temp);

    rebrick_util_addr_to_ip_string(&clientdata->bind_addr, ip_buffer);
    rebrick_log_debug("connected client from %s\n", ip_buffer);

    clientdata->handle.data=client;
    clientdata->after_connection_closed=serversocketdata->after_connection_closed;
    clientdata->after_data_received=serversocketdata->after_data_received;
    clientdata->after_data_sended=serversocketdata->after_data_sended;
    clientdata->parent=serversockethandle;


    if (serversocketdata->after_connection_accepted)
    {

        DL_APPEND(serversocketdata->clients,clientdata);
        serversocketdata->after_connection_accepted(&clientdata->bind_addr.base,client);

    }


    //start reading client
    uv_stream_t *tmp=cast(&clientdata->handle,uv_stream_t*);
    uv_read_start(tmp, on_alloc, on_recv);
        //burada kaldım.
}

static int32_t create_socket(rebrick_async_tcpsocket_t *data, int32_t backlog)
{
    char current_time_str[32] = {0};
    int32_t result;
    rebrick_async_tcpsocket_data_t *socket = cast(data->data, rebrick_async_tcpsocket_data_t *);
    socket->loop = uv_default_loop();
    result = uv_tcp_init(socket->loop, &socket->handle);
    if (result < 0)
    {
        // TODO: make it thread safe
        rebrick_log_fatal("socket failed:%s\n", uv_strerror(result));
        return REBRICK_ERR_UV + result;
    }

    result = uv_tcp_bind(&socket->handle, &socket->bind_addr.base, 0);
    if (result < 0)
    {
        rebrick_log_fatal("socket failed:%s\n", uv_strerror(result));
        return REBRICK_ERR_UV + result;
    }

    result = uv_listen(cast(&socket->handle,uv_stream_t*), backlog, on_connection);
    if (result < 0)
    {
        rebrick_log_fatal("socket failed:%s\n", uv_strerror(result));
        return REBRICK_ERR_UV + result;
    }
    rebrick_log_info("socket started at %s port:%s\n", socket->bind_ip, socket->bind_port);
    socket->handle.data = socket;

    return REBRICK_SUCCESS;
}

int32_t rebrick_async_tcpsocket_new(rebrick_async_tcpsocket_t **socket,
                                    rebrick_sockaddr_t bind_addr,
                                    void *callback_data,
                                    rebrick_after_connection_accepted_callback_t after_connection_accepted,
                                    rebrick_after_connection_closed_callback_t after_connection_closed,
                                    rebrick_after_data_received_callback_t after_data_received,
                                    rebrick_after_data_sended_callback_t after_data_sended, int32_t backlog)
{
    char current_time_str[32] = {0};
    int32_t result;
    rebrick_async_tcpsocket_t *tmp = new (rebrick_async_tcpsocket_t);
    constructor(tmp, rebrick_async_tcpsocket_t, "rebrick_async_tcpsocket_t");

    rebrick_async_tcpsocket_data_t *data = new (rebrick_async_tcpsocket_data_t);
    constructor(data, rebrick_async_tcpsocket_data_t, "rebrick_async_tcpsocket_data_t");
    //burası önemli,callback data
    data->callback_data = callback_data;

    data->bind_addr = bind_addr;
    rebrick_util_addr_to_ip_string(&data->bind_addr, data->bind_ip);
    rebrick_util_addr_to_port_string(&data->bind_addr, data->bind_port),

    data->after_data_received = after_data_received;
    data->after_data_sended = after_data_sended;
    data->after_connection_accepted = after_connection_accepted;
    data->after_connection_closed=after_connection_closed;

    tmp->data = data;
    result = create_socket(tmp, backlog);
    if (result < 0)
    {
        rebrick_log_fatal("create socket failed bind at %s port:%s\n", data->bind_ip, data->bind_port);
        free(data);
        free(tmp);
        return result;
    }

    *socket = tmp;
    return REBRICK_SUCCESS;
}

static void on_close(uv_handle_t *handle)
{
    char current_time_str[32] = {0};
    unused(current_time_str);
    if (handle)
        if (handle->data)
        {
            rebrick_async_tcpsocket_t *socket = cast(handle->data, rebrick_async_tcpsocket_t *);
            if (socket->data){
                rebrick_async_tcpsocket_data_t *data=cast(socket->data,rebrick_async_tcpsocket_data_t*);
                if(data->after_connection_closed){
                    rebrick_log_debug("handle closed\n");
                    data->after_connection_closed(data->callback_data);
                }
                if(data->parent){
                    rebrick_async_tcpsocket_data_t *dataparent=cast(data->parent->data,rebrick_async_tcpsocket_data_t*);
                    DL_DELETE(dataparent->clients,data);
                }
                free(socket->data);
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
        rebrick_async_tcpsocket_data_t *data = cast(socket->data, rebrick_async_tcpsocket_data_t *);
        uv_handle_t *handle = cast(&data->handle, uv_handle_t *);
        if (!uv_is_closing(handle))
        {

            rebrick_log_info("closing connection %s port:%s\n", data->bind_ip, data->bind_port);
            uv_close(handle, on_close);
        }
    }
    return REBRICK_SUCCESS;
}