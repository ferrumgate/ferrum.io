#include "rebrick_async_tlssocket.h"

/**
 * @brief client yada ssl olduğu için biz
 * içerden rebrick_async_tcpsocket_send yapıyoruz
 * bu fonksiyon da aftersend_data isimli bir parametre alıyor
 * ve callback fonksiyona geçiyor.
 *
 */
#define REBRICK_BUFFER_MALLOC_SIZE 8192
#define BUF_SIZE 8192




private_ typedef struct send_data_holder
{
    base_object();
    private_ rebrick_clean_func_t *client_data;
    private_ void *internal_data;
    private_ size_t internal_data_len;
} send_data_holder_t;

enum sslstatus
{
    SSLSTATUS_OK,
    SSLSTATUS_WANT_READ,
    SSLSTATUS_WANT_WRITE,
    SSLSTATUS_FAIL
};

static enum sslstatus get_sslstatus(SSL *ssl, int n)
{

    switch (SSL_get_error(ssl, n))
    {
    case SSL_ERROR_NONE:
        // printf("ssl status ok\n");
        return SSLSTATUS_OK;
    case SSL_ERROR_WANT_WRITE:
        //printf("ssl status write\n");
        return SSLSTATUS_WANT_WRITE;
    case SSL_ERROR_WANT_READ:
        //printf("ssl status read\n");
        return SSLSTATUS_WANT_READ;
    case SSL_ERROR_ZERO_RETURN:
    case SSL_ERROR_SYSCALL:
    default:
        return SSLSTATUS_FAIL;
    }
}
char sslerror[4096];
char * getOpenSSLError()
{
    BIO *bio = BIO_new(BIO_s_mem());
    ERR_print_errors(bio);
    char *buf;
    size_t len = BIO_get_mem_data(bio, &buf);
    size_t strlen=sizeof(sslerror);
    memset(sslerror,0,strlen);
    memcpy(sslerror,buf,len<strlen?len:(strlen-1));
    BIO_free(bio);
    return sslerror;
}

static void clean_send_data_holder(void *ptr){
    send_data_holder_t *senddata=cast(ptr,send_data_holder_t*);
    if(senddata && senddata->internal_data)
    free(senddata->internal_data);
    if(senddata && senddata->client_data)
    {

        if(senddata->client_data->func)
        senddata->client_data->func(senddata->client_data->ptr);
        free(senddata->client_data);
    }
    if(senddata)
    free(senddata);
}

static int32_t check_ssl_status(rebrick_async_tlssocket_t *tlssocket, int32_t n)
{
    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;

    enum sslstatus status;
    char buftemp[BUF_SIZE] = {0};
    if (!tlssocket || !tlssocket->tls)
    {
        rebrick_log_fatal("socket tls is null\n");
        return REBRICK_ERR_BAD_ARGUMENT;
    }

    status = get_sslstatus(tlssocket->tls->ssl, n);


    if (status == SSLSTATUS_WANT_READ)
    {
        rebrick_log_debug("ssl want read\n");
        do
        {
            n = BIO_read(tlssocket->tls->write, buftemp, sizeof(buftemp));

            if (n > 0)
            {
                char *xbuf = malloc(n);
                memcpy(xbuf, buftemp, n);
                send_data_holder_t *holder = new (send_data_holder_t);
                constructor(holder, send_data_holder_t);
                holder->internal_data = xbuf;
                holder->internal_data_len = n;
                holder->client_data = NULL;

                rebrick_clean_func_t cleanfunc={.func=clean_send_data_holder,.ptr=holder};
                result = rebrick_async_tcpsocket_send(cast_to_tcp_socket(tlssocket), buftemp, n, cleanfunc);

                if (result < 0)
                {
                    free(xbuf);
                    free(holder);
                    return result;
                }
            }
            else if (!BIO_should_retry(tlssocket->tls->write))
            {

                return REBRICK_ERR_TLS_ERR;
            }

        } while (n > 0);
    }
    if (status == SSLSTATUS_WANT_WRITE)
    {
        rebrick_log_debug("ssl want write\n");
        // printf("ssl status wirte tls error\n");
        return REBRICK_ERR_TLS_ERR;
    }
    if (status == SSLSTATUS_FAIL)
    {
        rebrick_log_error("ssl failed\n");
        //printf("ssl status wirte tls error2\n");
        return REBRICK_ERR_TLS_ERR;
    }

    if (!SSL_is_init_finished(tlssocket->tls->ssl))
        return REBRICK_ERR_TLS_INIT_NOT_FINISHED;
    return REBRICK_SUCCESS;
}

void flush_buffers(struct rebrick_async_tlssocket *tlssocket)
{

    char current_time_str[32] = {0};
    unused(current_time_str);
    char buftemp[BUF_SIZE];


    if (tlssocket && tlssocket->pending_write_list)
    {

        int32_t result;

        rebrick_log_debug("pending read list try to send\n");

        size_t len = 0;
        int32_t error_occured = 0;
        struct pending_data *el, *tmp;
        DL_FOREACH_SAFE(tlssocket->pending_write_list, el, tmp)
        {
            char *tmpbuffer = NULL;
            result = rebrick_buffer_to_array(el->data, &tmpbuffer, &len);
            int32_t writen_len = 0;
            int32_t temp_len = len;
            error_occured = 0;
            while (writen_len < temp_len)
            {
                int32_t n = SSL_write(tlssocket->tls->ssl, (const void *)(tmpbuffer + writen_len), temp_len - writen_len);
                result = check_ssl_status(tlssocket, n);

                if(result==REBRICK_ERR_TLS_ERR){
                    rebrick_log_error("tls failed\n");

                    error_occured=1;
                    free(tmpbuffer);
                    if(tlssocket->after_data_sended)
                    tlssocket->after_data_sended(cast_to_base_socket(tlssocket),tlssocket->override_callback_data,NULL, REBRICK_ERR_TLS_ERR);
                    //TODO burası üzerinde çalışmak lazım


                    break;


                }else
                if (result != REBRICK_SUCCESS)
                {

                    error_occured = 1;
                    free(tmpbuffer);
                    break;
                }

                if (n > 0)
                {
                    writen_len += n;

                    do
                    {
                        n = BIO_read(tlssocket->tls->write, buftemp, sizeof(buftemp));
                        if (n > 0)
                        {

                            send_data_holder_t *holder = new (send_data_holder_t);
                            constructor(holder, send_data_holder_t);
                            holder->internal_data = tmpbuffer;
                            holder->internal_data_len = len;
                            holder->client_data = el->clean_func;

                            rebrick_clean_func_t cleanfunc={.func=clean_send_data_holder,.ptr=holder};
                            //client datası olduğunu belirtmek için source 1 yapılıyor
                            cleanfunc.anydata.source=1;
                            result = rebrick_async_tcpsocket_send(cast_to_tcp_socket(tlssocket), buftemp, n, cleanfunc);
                            if (result < 0)
                            {
                                free(holder);
                                free(tmpbuffer);
                            }
                            rebrick_buffer_destroy(el->data);

                            el->data = NULL;
                        }
                        else if (!BIO_should_retry(tlssocket->tls->write))
                        {
                            error_occured = 1;
                            break;
                        }

                    } while (n > 0);
                }
            }

            if (!error_occured)
            {
                DL_DELETE(tlssocket->pending_write_list, el);
                free(el);
            }
            else
            {
                break;
            }
        }
    }
}

/**
 * @brief checs ssl status
 *
 * @param tlssocket
 * @return int32_t REBRICK_ERR_BAD_ARGUMENT,REBRICK_ERR_TLS_ERR,REBRICK_ERR_TLS_INIT_NOT_FINISHED,REBRICK_SUCCESS
 */
static int32_t ssl_handshake(rebrick_async_tlssocket_t *tlssocket)
{
    char current_time_str[32] = {0};
    unused(current_time_str);
    //int32_t result;
    int32_t n;
    //enum sslstatus status;
    //char buftemp[BUF_SIZE];

    if (!tlssocket && !tlssocket->tls)
    {
        rebrick_log_fatal("socket tls is null\n");
        return REBRICK_ERR_BAD_ARGUMENT;
    }

    if (!tlssocket->sslhandshake_initted)
    {

        if (tlssocket->tls_context->is_server)
            n = SSL_accept(tlssocket->tls->ssl);
        else
            n = SSL_connect(tlssocket->tls->ssl);

        if (n == 1 || get_sslstatus(tlssocket->tls->ssl, n) == SSLSTATUS_WANT_READ)
        {
            tlssocket->sslhandshake_initted = 1;
            return n;
        }

        return REBRICK_ERR_TLS_ERR;
    }

    return REBRICK_SUCCESS;
}

#define call_after_connection(tlsserver, tlsclient, status)                                                                                                              \
    if (tlsserver && tlsclient && !tlsclient->called_override_after_connection_accepted && tlsclient->override_after_connection_accepted)                                \
    {                                                                                                                                                                    \
        tlsclient->called_override_after_connection_accepted++;                                                                                                          \
        tlsclient->override_after_connection_accepted(cast_to_base_socket(tlsserver), tlsclient->override_callback_data, &tlsclient->bind_addr.base, tlsclient, status); \
    }

static int32_t local_after_connection_accepted_callback(rebrick_async_socket_t *serversocket, void *callback_data, const struct sockaddr *addr, void *client_handle, int status)
{

    char current_time_str[32] = {0};
    unused(current_time_str);
    unused(addr);
    unused(callback_data);
    int32_t result;

    //printf("connected client\n");
    rebrick_async_tlssocket_t *tlsserver = cast(serversocket, rebrick_async_tlssocket_t *);

    if (!tlsserver)
    {
        rebrick_log_fatal("callback_data casting is null\n");
        return REBRICK_ERR_BAD_ARGUMENT;
    }

    rebrick_async_tlssocket_t *tlsclient = NULL;
    //server ise client_handle yeni handle'dır yoksa, server handle ile aynıdır
    if (tlsserver->tls_context->is_server)
        tlsclient = cast(client_handle, rebrick_async_tlssocket_t *);
    else
        tlsclient = tlsserver;

    if (status)
    {
        rebrick_log_fatal("connection accepted failed with error:%d\n", status);
        if (tlsserver->override_after_connection_accepted)
            tlsserver->override_after_connection_accepted(cast_to_base_socket(tlsserver), tlsserver->override_callback_data, NULL, NULL, status);
        return status;
    }

    //bağlandığında client yada server-client için yeni bir ssl oluşturulur
    rebrick_tls_ssl_t *tls_ssl;
    result = rebrick_tls_ssl_new(&tls_ssl, tlsserver->tls_context);
    if (result)
    {
        if (tlsserver->tls_context->is_server)
            rebrick_async_tlssocket_destroy(tlsclient);
        client_handle = NULL;
        rebrick_log_fatal("ssl new failed for %s\n", tlsserver->tls_context->key);
        if (tlsserver->override_after_connection_accepted)
            tlsserver->override_after_connection_accepted(cast_to_base_socket(tlsserver), tlsserver->override_callback_data, NULL, NULL, status);
        return result;
    }

    //base sınıfta olmayan kısımlar burada implemente edilmeli
    tlsclient->tls_context = tlsserver->tls_context;
    tlsclient->tls = tls_ssl;

    tlsclient->override_after_connection_accepted = tlsserver->override_after_connection_accepted;
    tlsclient->override_after_connection_closed = tlsserver->override_after_connection_closed;
    tlsclient->override_after_data_received = tlsserver->override_after_data_received;
    tlsclient->override_after_data_sended = tlsserver->override_after_data_sended;
    tlsclient->override_callback_data = tlsserver->override_callback_data;
    //tlsclient için callback_data kendisi geçilir.
    tlsclient->callback_data = tlsclient;

    status = ssl_handshake(tlsclient);

    if (status)
    {

        if (status == REBRICK_ERR_BAD_ARGUMENT)
        {
            if (tlsserver->tls_context->is_server)
                rebrick_async_tlssocket_destroy(tlsclient);
            client_handle = NULL;
            rebrick_log_fatal("connection accepted failed with error:%d\n", status);
            if (tlsserver->override_after_connection_accepted)
                tlsserver->override_after_connection_accepted(cast_to_base_socket(tlsserver), tlsserver->override_callback_data, NULL, NULL, status);
            return status;
        }
        status = check_ssl_status(tlsclient, status);
        if (status == REBRICK_SUCCESS || status == REBRICK_ERR_TLS_INIT_NOT_FINISHED)
        {
            //ssl problemi yok ise, her loop sonrası çalışacak kod ekleniyor
            rebrick_after_io_list_add(flush_buffers, tlsclient);
        }
        else
        {
            //null koruması var
            //burası nasıl silinmeli acaba
            if (tlsserver->tls_context->is_server)
                rebrick_async_tlssocket_destroy(tlsclient);
            client_handle = NULL;
            status = REBRICK_ERR_TLS_INIT;
            rebrick_log_fatal("connection accepted failed with error:%d\n", status);
            if (tlsserver->override_after_connection_accepted)
                tlsserver->override_after_connection_accepted(cast_to_base_socket(tlsserver), tlsserver->override_callback_data, NULL, NULL, status);
            return status;
        }

        //this function triggers, if tls client is successfully connected

        call_after_connection(tlsserver, tlsclient, 0);
    }

    return REBRICK_SUCCESS;
}

static int32_t local_after_connection_closed_callback(rebrick_async_socket_t *socket, void *callback_data)
{

    char current_time_str[32] = {0};
    unused(current_time_str);
    unused(callback_data);
    rebrick_async_tlssocket_t *tlssocket = cast(socket, rebrick_async_tlssocket_t *);
    //printf("connection closed\n");
    if (!tlssocket)
    {
        rebrick_log_fatal("callback_data casting is null\n");
        return REBRICK_ERR_BAD_ARGUMENT;
    }
    rebrick_after_io_list_remove(tlssocket);

    rebrick_tls_ssl_destroy(tlssocket->tls);

    tlssocket->tls = NULL;

    pending_data_t *el, *tmp;
    DL_FOREACH_SAFE(tlssocket->pending_write_list, el, tmp)
    {
        rebrick_buffer_destroy(el->data);
        DL_DELETE(tlssocket->pending_write_list, el);
        rebrick_clean_func_t  *deletedata=el->clean_func;
        free(el);
        if(deletedata){
            if(deletedata->func){

                deletedata->func(deletedata->ptr);
            }
            free(deletedata);
        }


    }

    if (tlssocket->override_after_connection_closed)
        tlssocket->override_after_connection_closed(cast_to_base_socket(tlssocket), tlssocket->override_callback_data);

    return REBRICK_SUCCESS;
}

static int32_t local_after_data_received_callback(rebrick_async_socket_t *socket, void *callback_data, const struct sockaddr *addr, const char *buffer, ssize_t len)
{

    char current_time_str[32] = {0};
    unused(current_time_str);
    unused(callback_data);
    int32_t result;
    int32_t n;
    int32_t status;

    rebrick_async_tlssocket_t *tlssocket = cast(socket, rebrick_async_tlssocket_t *);

    char buftemp[4096];
    if (!tlssocket)
    {

        rebrick_log_fatal("callback_data casting is null\n");
        return REBRICK_ERR_BAD_ARGUMENT;
    }

    if(len<=0){
          rebrick_log_error("socket io error %" PRId64 "\n",len);
          if(tlssocket->override_after_data_received)
          tlssocket->override_after_data_received(cast_to_base_socket(tlssocket), tlssocket->override_callback_data, addr, NULL, len);
          return len;
    }



    rebrick_buffer_t *readedbuffer = NULL;
    size_t tmp_len = len;
    while (tmp_len)
    {

        n = BIO_write(tlssocket->tls->read, buffer, tmp_len);
        if (n <= 0)
        {
            rebrick_log_error("ssl bio write failed\n");
            rebrick_buffer_destroy(readedbuffer);
            if(tlssocket->override_after_data_received)
            tlssocket->override_after_data_received(cast_to_base_socket(tlssocket), tlssocket->override_callback_data, addr, NULL, REBRICK_ERR_TLS_WRITE);
            return REBRICK_ERR_TLS_WRITE;
        }
        buffer += n;
        tmp_len -= n;

        result = check_ssl_status(tlssocket, n);

        if (result == REBRICK_ERR_TLS_INIT_NOT_FINISHED)
        {

            continue;
        }
        else if (result < 0)
        {

            rebrick_log_error("ssl status failed 1 %d:%d\n",n, result);
            rebrick_buffer_destroy(readedbuffer);
            if(tlssocket->override_after_data_received)
            tlssocket->override_after_data_received(cast_to_base_socket(tlssocket), tlssocket->override_callback_data, addr, NULL, result);
            return result;
        }

        do
        {

            n = SSL_read(tlssocket->tls->ssl, buftemp, sizeof(buftemp));

            if (n > 0)
            {

                //okunan byteları
                if (!readedbuffer)
                    rebrick_buffer_new(&readedbuffer, (uint8_t *)buftemp, (size_t)n, REBRICK_BUFFER_MALLOC_SIZE);
                else
                    rebrick_buffer_add(readedbuffer, (uint8_t *)buftemp, (size_t)n);
            }
        } while (n > 0);
        status = check_ssl_status(tlssocket, n);

        if (status==REBRICK_ERR_TLS_ERR)
        {
             rebrick_log_error("ssl status failed 2 %d:%d\n",n,status);
            rebrick_buffer_destroy(readedbuffer);
            if(tlssocket->override_after_data_received)
           tlssocket->override_after_data_received(cast_to_base_socket(tlssocket), tlssocket->override_callback_data, addr, NULL, status);

            return status;
        }
    }

    //call_after_connection(parentsocket_or_self, tlssocket, result);

    if (tlssocket->override_after_data_received)
    {
        size_t array_len = 0;
        char *array;
        result = rebrick_buffer_to_array(readedbuffer, &array, &array_len);

        if (array_len)
        {
            tlssocket->override_after_data_received(cast_to_base_socket(tlssocket), tlssocket->override_callback_data, addr, array, array_len);
            free(array);
        }
    }

    rebrick_buffer_destroy(readedbuffer);
    return REBRICK_SUCCESS;
}

static int32_t local_after_data_sended_callback(rebrick_async_socket_t *socket, void *callback_data,void *source, int status)
{

    char current_time_str[32] = {0};
    unused(current_time_str);
    unused(callback_data);
    unused(status);
    rebrick_async_tlssocket_t *tlssocket = cast(socket, rebrick_async_tlssocket_t *);
    if (!tlssocket)
    {
        rebrick_log_fatal("callback_data casting is null\n");
        return REBRICK_ERR_BAD_ARGUMENT;
    }

    //burası önemli, flush_ssl_buffer yaptığımızda



    if(source)//eğer gönderilen data client datası ise
    if (tlssocket->override_after_data_sended)
        tlssocket->override_after_data_sended(cast_to_base_socket(tlssocket), tlssocket->override_callback_data,NULL,status);



    return REBRICK_SUCCESS;
}

///burada ssl socket oluşturmamız lazım
//bu fonksiyon çalışırsa inheritance çalışıyor demektirki
//function overloading te çalışıyor.
///muhahahahaha
static struct rebrick_async_tcpsocket *local_create_client()
{
    char current_time_str[32] = {0};
    unused(current_time_str);
    rebrick_async_tlssocket_t *client = new (rebrick_async_tlssocket_t);
    constructor(client, rebrick_async_tlssocket_t);
    return cast(client, rebrick_async_tcpsocket_t *);
}



int32_t rebrick_async_tlssocket_init(rebrick_async_tlssocket_t *tlssocket, const rebrick_tls_context_t *tls_context, rebrick_sockaddr_t addr, void *callback_data,
                                    rebrick_after_connection_accepted_callback_t after_connection_accepted,
                                    rebrick_after_connection_closed_callback_t after_connection_closed,
                                    rebrick_after_data_received_callback_t after_data_received,
                                    rebrick_after_data_sended_callback_t after_data_sended, int32_t backlog_or_isclient)
{

    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;

    if (!tls_context)
    {
        rebrick_log_fatal("tls context is null\n");
        return REBRICK_ERR_BAD_ARGUMENT;
    }

    if (tls_context->is_server && !backlog_or_isclient)
    {
        rebrick_log_fatal("tls context is server but backlog_or_isclient parameter is 0\n");
        return REBRICK_ERR_BAD_ARGUMENT;
    }
    if (!tls_context->is_server && backlog_or_isclient)
    {
        rebrick_log_fatal("tls context is client but backlog_or_isclient parameter is > 0\n");
        return REBRICK_ERR_BAD_ARGUMENT;
    }


    tlssocket->override_after_connection_accepted = after_connection_accepted;
    tlssocket->override_after_connection_closed = after_connection_closed;
    tlssocket->override_after_data_received = after_data_received;
    tlssocket->override_after_data_sended = after_data_sended;
    tlssocket->override_callback_data = callback_data;
    tlssocket->tls_context = tls_context;
    //
    //this is OOP inheritnace with c
    //base class init function call.
    result = rebrick_async_tcpsocket_init(cast_to_tcp_socket(tlssocket), addr, tlssocket, local_after_connection_accepted_callback,
                                          local_after_connection_closed_callback, local_after_data_received_callback, local_after_data_sended_callback, backlog_or_isclient, local_create_client);
    if (result)
    {
        int32_t uv_err = HAS_UV_ERR(result) ? UV_ERR(result) : 0;
        rebrick_log_fatal("tcpsocket create failed with result:%d %s\n", result, uv_strerror(uv_err));
        return result;
    }

    return REBRICK_SUCCESS;
}


int32_t rebrick_async_tlssocket_new(rebrick_async_tlssocket_t **socket, const rebrick_tls_context_t *tls_context, rebrick_sockaddr_t addr, void *callback_data,
                                    rebrick_after_connection_accepted_callback_t after_connection_accepted,
                                    rebrick_after_connection_closed_callback_t after_connection_closed,
                                    rebrick_after_data_received_callback_t after_data_received,
                                    rebrick_after_data_sended_callback_t after_data_sended, int32_t backlog_or_isclient)
{

    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;

     rebrick_async_tlssocket_t *tlssocket = new (rebrick_async_tlssocket_t);
    constructor(tlssocket, rebrick_async_tlssocket_t);
    result=rebrick_async_tlssocket_init(tlssocket,tls_context,addr,callback_data,after_connection_accepted,after_connection_closed,after_data_received,after_data_sended,backlog_or_isclient);
    if(result<0){
        free(tlssocket);
        rebrick_log_error("tls socket init failed with:%d\n",result);
        return result;
    }

     *socket = tlssocket;
    return REBRICK_SUCCESS;
}

int32_t rebrick_async_tlssocket_destroy(rebrick_async_tlssocket_t *socket)
{
    char current_time_str[32] = {0};
    unused(current_time_str);
    //rebrick_log_debug("tls socket is closing\n");
    if (socket)
    {
        //buraya başka kod yazmaya gerek yok
          if(socket->parent_socket){
         int32_t result=SSL_shutdown(socket->tls->ssl);
         check_ssl_status(socket,result);

        }else{
            rebrick_async_tcpsocket_t *el,*tmp;
            DL_FOREACH_SAFE(socket->clients,el,tmp){
                rebrick_async_tlssocket_t *tsocket=cast(el,rebrick_async_tlssocket_t*);
                 int32_t result=SSL_shutdown(tsocket->tls->ssl);
                check_ssl_status(tsocket,result);

            }
        }
        rebrick_async_tcpsocket_destroy(cast_to_tcp_socket(socket));

        //free(socket) yapmakmak lazım, zaten tcpsocket yapıyor
    }
    return REBRICK_SUCCESS;
}

int32_t rebrick_async_tlssocket_send(rebrick_async_tlssocket_t *socket, char *buffer, size_t len, rebrick_clean_func_t cleanfuncs)
{
    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;
    int32_t n;
    unused(result);
    char buftemp[BUF_SIZE];
    if (uv_is_closing(cast(&socket->handle.tcp, uv_handle_t *)))
    {
        return REBRICK_ERR_IO_CLOSED;
    }

    rebrick_buffer_t *buffertmp = NULL;
    int32_t writen_len = 0;
    int32_t temp_len = len;
    while (writen_len < temp_len)
    {
        n = SSL_write(socket->tls->ssl, (const void *)(buffer + writen_len), temp_len - writen_len);
        result = check_ssl_status(socket, n);

        if (n > 0)
        {
            writen_len += n;

            do
            {
                n = BIO_read(socket->tls->write, buftemp, sizeof(buftemp));
                if (n > 0)
                {
                    if (!buffertmp)
                        rebrick_buffer_new(&buffertmp, (uint8_t *)buftemp, (size_t)n, REBRICK_BUFFER_MALLOC_SIZE);
                    else
                        rebrick_buffer_add(buffertmp, (uint8_t *)buftemp, (size_t)n);
                }
                else if (!BIO_should_retry(socket->tls->write))
                {

                    return REBRICK_ERR_TLS_ERR;
                }

            } while (n > 0);
        }
        else if (result == REBRICK_ERR_TLS_INIT_NOT_FINISHED)
        {
            //ssl problemli ise sonra yazalım
            pending_data_t *data = new (pending_data_t);
            constructor(data, pending_data_t);
            rebrick_buffer_new(&data->data, (uint8_t *)(buffer + writen_len), (size_t)(temp_len - writen_len), REBRICK_BUFFER_MALLOC_SIZE);

            rebrick_clean_func_clone(&cleanfuncs,data->clean_func);


            DL_APPEND(socket->pending_write_list, data);
            break;
        }
        else if (result==REBRICK_ERR_TLS_ERR)
        {
            rebrick_log_error("tls failed\n");
            rebrick_buffer_destroy(buffertmp);
            return result;
        }
    }

    if (buffertmp)
    {
        char *tmpbuffer = NULL;
        size_t tmplen = 0;
        rebrick_buffer_to_array(buffertmp, &tmpbuffer, &tmplen);
        if (tmplen)
        {
            send_data_holder_t *holder = new (send_data_holder_t);
            constructor(holder, send_data_holder_t);
            holder->internal_data = tmpbuffer;
            holder->internal_data_len = len;
            rebrick_clean_func_clone(&cleanfuncs,holder->client_data);

            rebrick_clean_func_t cleanfunc={.func=clean_send_data_holder,.ptr=holder};
            //client datası olduğunu belirtmek için source 1 yapılıyor
            cleanfunc.anydata.source=1;
            result = rebrick_async_tcpsocket_send(cast_to_tcp_socket(socket), tmpbuffer, tmplen, cleanfunc);
            if (result < 0)
            {
                free(holder);
                free(tmpbuffer);
            }
        }
        rebrick_buffer_destroy(buffertmp);
    }

    flush_buffers(socket);



    return REBRICK_SUCCESS;
}