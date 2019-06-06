#include "rebrick_async_udpsocket.h"

private typedef struct rebrick_async_udpsocket_data{
    base_class();
    char bind_ip[REBRICK_IP_STR_LEN];
    char bind_port[REBRICK_PORT_STR_LEN];

    uv_loop_t *loop;
    uv_udp_t handle;
    rebrick_sockaddr_t bind_addr;
    rebrick_after_data_received_callback_t after_data_received;
    rebrick_after_data_sended_callback_t after_data_sended;

    /**
     * @brief customer user data for every callback
     *
     */
    void *callback_data;


}rebrick_async_udpsocket_data_t;


static void on_send(uv_udp_send_t *req, int status)
{
    // TODO: status a göre işlem yapılmalı

    char current_time_str[32] = {0};

    unused(current_time_str);
    rebrick_log_debug("socket on send called and status:%d\n",status);
    if (req->data)
    {
        char *data = cast(req->data, char *);
        if (data)
        {

           free(data);
        }
    }
    if(req->handle)
    if(req->handle->data){
        const rebrick_async_udpsocket_data_t *socket = cast(req->handle->data, rebrick_async_udpsocket_data_t *);
        if(socket->after_data_sended)
        socket->after_data_sended(socket->callback_data, status);
    }
    free(req);


}
int32_t rebrick_async_udpsocket_send(rebrick_async_udpsocket_t *socket,rebrick_sockaddr_t *dstaddr, char *buffer,size_t len)
{

    char current_time_str[32] = {0};
    char dst_ip[REBRICK_IP_STR_LEN];
    char dst_port[REBRICK_PORT_STR_LEN];
    int32_t result;
    rebrick_async_udpsocket_data_t *data = cast(socket->data, rebrick_async_udpsocket_data_t *);
    uv_udp_send_t* request = new(uv_udp_send_t);
    fill_zero(request,sizeof(uv_udp_send_t));
    uv_buf_t buf=uv_buf_init(buffer,len);
    //rebrick_dns_t türünde paket olduğundan cache te duracak
    //request->data = buf.base;
    result = uv_udp_send(request, &data->handle, &buf, 1, &dstaddr->base, on_send);
    rebrick_util_addr_to_ip_string(dstaddr,dst_ip);
    rebrick_util_addr_to_port_string(dstaddr,dst_port);
    if (result < 0)
    {

        rebrick_log_info("sending data to server %s port:%s failed\n", dst_ip,dst_port);
        return REBRICK_ERR_UV+result;
    }
    rebrick_log_debug("data sended  len:%zu to server  %s port:%s\n",len,dst_ip,dst_port);
    return REBRICK_SUCCESS;
}

static void on_recv(uv_udp_t *handle, ssize_t nread, const uv_buf_t *rcvbuf, const struct sockaddr *addr, unsigned flags)
{

    char current_time_str[32] = {0};
    unused(current_time_str);
    unused(flags);
    const rebrick_async_udpsocket_data_t *socket = cast(handle->data, rebrick_async_udpsocket_data_t *);


    rebrick_log_debug("socket receive nread:%zd buflen:%zu\n",nread,rcvbuf->len);
    if (nread <= 0)//burası silinirse,
    {

        rebrick_log_debug("nread is <=0 from %s port %s\n", socket->bind_ip,socket->bind_port);
        free(rcvbuf->base);
        return;
    }

    if(socket)
    if(socket->after_data_received && nread>0){
        //nread ssize_t olmasına karşın parametre olarak geçildi
        //neticed eğer nread<0 zaten buraya gelmiyor
    socket->after_data_received(socket->callback_data, addr, rcvbuf->base,nread);
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
    if (!buf)
    {
        rebrick_log_fatal("malloc problem at socket");
        exit(1);
    }
    buf->len = suggested_size;
    fill_zero(buf->base,buf->len);
    rebrick_log_debug("malloc socket:%lu %p\n", buf->len, buf->base);
}


static  int32_t create_socket(rebrick_async_udpsocket_t *data){
 char current_time_str[32] = {0};

    int32_t result;
    rebrick_async_udpsocket_data_t *socket=cast(data->data,rebrick_async_udpsocket_data_t*);
    socket->loop = uv_default_loop();
    result = uv_udp_init(socket->loop, &socket->handle);
    if (result < 0)
    {
        // TODO: burası multi thread değil
        rebrick_log_fatal("socket failed:%s\n", uv_strerror(result));
        return REBRICK_ERR_UV + result;
    }

    result = uv_udp_bind(&socket->handle, &socket->bind_addr.base, 0);
    if (result < 0)
    {
        rebrick_log_fatal("socket failed:%s\n", uv_strerror(result));
        return REBRICK_ERR_UV + result;
    }

    result = uv_udp_recv_start(&socket->handle, on_alloc, on_recv);
    if (result < 0)
    {
        rebrick_log_fatal("socket failed:%s\n", uv_strerror(result));
        return REBRICK_ERR_UV + result;
    }
    rebrick_log_info("socket started at %s port:%s\n", socket->bind_ip,socket->bind_port);
    socket->handle.data = socket;

    return REBRICK_SUCCESS;
}

int32_t rebrick_async_udpsocket_new(rebrick_async_udpsocket_t **socket,
rebrick_sockaddr_t bind_addr,
void *callback_data,
rebrick_after_data_received_callback_t after_data_received,
rebrick_after_data_sended_callback_t after_data_sended){

    char current_time_str[32] = {0};
    int32_t result;
    rebrick_async_udpsocket_t *tmp=new(rebrick_async_udpsocket_t);
    constructor(tmp,rebrick_async_udpsocket_t,"rebrick_async_udpsocket_t");

    rebrick_async_udpsocket_data_t *data=new(rebrick_async_udpsocket_data_t);
    constructor(data,rebrick_async_udpsocket_data_t,"rebrick_async_udpsocket_data_t");


    //burası önemli,callback data
    data->callback_data=callback_data;

    data->bind_addr=bind_addr;
    rebrick_util_addr_to_ip_string(&data->bind_addr,data->bind_ip);
    rebrick_util_addr_to_port_string(&data->bind_addr,data->bind_port),


    data->after_data_received=after_data_received;
    data->after_data_sended=after_data_sended;

    tmp->data=data;
    result=create_socket(tmp);
    if(result<0){
        rebrick_log_fatal("create socket failed bind at %s port:%s\n",data->bind_ip,data->bind_port);
        free(data);
        free(tmp);
        return result;
    }

    *socket=tmp;
    return REBRICK_SUCCESS;



}

static void on_close(uv_handle_t *handle){
    if(handle)
    if(handle->data){
        rebrick_async_udpsocket_t *socket=cast(handle->data,rebrick_async_udpsocket_t*);
        if(socket->data)
        free(socket->data);
        free(socket);
    }

}


int32_t rebrick_async_udpsocket_destroy(rebrick_async_udpsocket_t *socket){
char current_time_str[32] = {0};
    if(socket){
            //close if server is ready
            rebrick_async_udpsocket_data_t *data=  cast(socket->data,rebrick_async_udpsocket_data_t *);
            uv_handle_t *handle=cast(&data->handle,uv_handle_t*);
            if(!uv_is_closing(handle)){

                rebrick_log_info("closing connection %s port:%s\n",data->bind_ip,data->bind_port);
                uv_close(handle,on_close);

            }
    }
    return REBRICK_SUCCESS;
}