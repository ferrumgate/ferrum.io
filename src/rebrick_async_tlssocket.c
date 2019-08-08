#include "rebrick_async_tlssocket.h"

/**
 * @brief client yada ssl olduğu için biz
 * içerden rebrick_async_tcpsocket_send yapıyoruz
 * bu fonksiyon da aftersend_data isimli bir parametre alıyor
 * ve callback fonksiyona geçiyor.
 *
 */
#define REBRICK_BUFFER_MALLOC_SIZE 8192

private_ typedef struct send_data_holder
{
    base_object();
    private_ void *client_data;
    private_ void *internal_data;
    private_ size_t internal_data_len;
} send_data_holder_t;

static int32_t check_ssl_init(rebrick_async_tlssocket_t *tlssocket);

void flush_buffers(struct rebrick_async_tlssocket *tlssocket)
{

    char current_time_str[32] = {0};
    unused(current_time_str);

    if (tlssocket && tlssocket->pending_write_list)
    {

        char *tmp = NULL;
        size_t len = 0;
        int32_t result;
        result = rebrick_buffer_to_array(tlssocket->pending_write_list, &tmp, &len);
        if (!result && len)
        {

            rebrick_buffer_destroy(tlssocket->pending_write_list);
            tlssocket->pending_write_list = NULL;

            send_data_holder_t *holder = new (send_data_holder_t);
            constructor(holder, send_data_holder_t);
            holder->internal_data = tmp;
            holder->internal_data_len=len;

            rebrick_async_tcpsocket_send(cast(tlssocket, rebrick_async_tcpsocket_t *), tmp, len, holder);
        }
    }
}

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
        printf("ssl status ok\n");
        return SSLSTATUS_OK;
    case SSL_ERROR_WANT_WRITE:
    printf("ssl status write\n");
    return SSLSTATUS_WANT_WRITE;
    case SSL_ERROR_WANT_READ:
    printf("ssl status read\n");
        return SSLSTATUS_WANT_READ;
    case SSL_ERROR_ZERO_RETURN:
    case SSL_ERROR_SYSCALL:
    default:
        return SSLSTATUS_FAIL;
    }
}

static int32_t check_ssl_init(rebrick_async_tlssocket_t *tlssocket)
{
    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;
    int32_t n;
    enum sslstatus status;
    char buftemp[4096];

    if(!tlssocket->tls){
        rebrick_log_fatal("socket tls is null\n");
    return REBRICK_ERR_BAD_ARGUMENT;
    }

    if (!SSL_is_init_finished(tlssocket->tls->ssl))
    {

        if (tlssocket->tls_context->is_server)
            n = SSL_accept(tlssocket->tls->ssl);
        else
            n = SSL_connect(tlssocket->tls->ssl);
        status = get_sslstatus(tlssocket->tls->ssl, n);

        if (status == SSLSTATUS_WANT_READ)
        {
            do
            {
                n = BIO_read(tlssocket->tls->write, buftemp, sizeof(buftemp));
                if (n > 0)
                {
                    if (tlssocket->pending_write_list)
                        result = rebrick_buffer_add(tlssocket->pending_write_list, (uint8_t *)buftemp, (size_t)n);
                    else
                        result = rebrick_buffer_new(&tlssocket->pending_write_list, (uint8_t *)buftemp, (size_t)n,REBRICK_BUFFER_MALLOC_SIZE);
                    if (result < 0)
                        return result;
                }
                else if (!BIO_should_retry(tlssocket->tls->write))
                {

                    return REBRICK_ERR_TLS_ERR;
                }

            } while (n > 0);
        }
        if(status==SSLSTATUS_WANT_WRITE){
           return REBRICK_ERR_TLS_ERR;
        }
        if (status == SSLSTATUS_FAIL)
            return REBRICK_ERR_TLS_ERR;

        if (!SSL_is_init_finished(tlssocket->tls->ssl))
            return REBRICK_ERR_TLS_INIT_NOT_FINISHED;


    }

if (SSL_is_init_finished(tlssocket->tls->ssl))
            {
                printf("ssl init finished\n");
            }

    return REBRICK_SUCCESS;
}


#define call_after_connection(tlsclient,status)   \
     if(tlsclient && !tlsclient->called_override_after_connection_accepted && tlsclient->override_after_connection_accepted){ \
            tlsclient->override_after_connection_accepted(tlsclient->override_callback_data,&tlsclient->bind_addr.base,tlsclient,status); \
            tlsclient->called_override_after_connection_accepted++; \
        } \



static int32_t local_after_connection_accepted_callback(void *callback_data, const struct sockaddr *addr, void *client_handle, int status)
{

    char current_time_str[32] = {0};
    unused(current_time_str);
    unused(addr);
    int32_t result;
    rebrick_async_tlssocket_t *tlsserver = cast(callback_data, rebrick_async_tlssocket_t *);

    if (!tlsserver)
    {
        rebrick_log_fatal("callback_data casting is null\n");
        return REBRICK_ERR_BAD_ARGUMENT;
    }

    rebrick_tls_ssl_t *tls_ssl;
    result = rebrick_tls_ssl_new(&tls_ssl, tlsserver->tls_context);
    if (result)
    {
        rebrick_log_fatal("ssl new failed for %s\n", tlsserver->tls_context->key);
        return result;
    }
    rebrick_async_tlssocket_t *tlsclient=NULL;
    //server ise client_handle yeni handle'dır yoksa, server handle ile aynıdır
    if(tlsserver->tls_context->is_server)
    tlsclient = cast(client_handle, rebrick_async_tlssocket_t *);
    else
    tlsclient=tlsserver;

    //base sınıfta olmayan kısımlar burada implemente edilmeli
    tlsclient->tls_context = tlsserver->tls_context;
    tlsclient->tls = tls_ssl;

    tlsclient->override_after_connection_accepted = tlsserver->override_after_connection_accepted;
    tlsclient->override_after_connection_closed = tlsserver->override_after_connection_closed;
    tlsclient->override_after_data_received = tlsserver->override_after_data_received;
    tlsclient->override_after_data_sended = tlsserver->override_after_data_sended;
    tlsclient->override_callback_data = tlsclient;


    status=check_ssl_init(tlsclient);

    if(status==REBRICK_ERR_BAD_ARGUMENT){
         if(tlsserver->tls_context->is_server)
        rebrick_async_tlssocket_destroy(tlsclient);
        client_handle = NULL;
        return status;
    }else
    if (status == REBRICK_SUCCESS || status == REBRICK_ERR_TLS_INIT_NOT_FINISHED)
    {
        //ssl problemi yok ise, her loop sonrası çalışacak kod ekleniyor
        rebrick_after_io_list_add(flush_buffers, tlsclient);
        flush_buffers(tlsclient);



    }
    else
    {
        //null koruması var
        //burası nasıl silinmeli acaba
        if(tlsserver->tls_context->is_server)
        rebrick_async_tlssocket_destroy(tlsclient);
        client_handle = NULL;
        status = REBRICK_ERR_TLS_INIT;



    }
    //ssl bittiğinde yada ssl problemi var ise
    if(status==REBRICK_SUCCESS || status==REBRICK_ERR_TLS_INIT){

       call_after_connection(tlsclient,status);


    }


    return REBRICK_SUCCESS;
}

static int32_t local_after_connection_closed_callback(void *callback_data)
{

    //TODO burası incelenmeli
    char current_time_str[32] = {0};
    unused(current_time_str);
    rebrick_async_tlssocket_t *tlssocket = cast(callback_data, rebrick_async_tlssocket_t *);
    printf("connection closed\n");
    if (!tlssocket)
    {
        rebrick_log_fatal("callback_data casting is null\n");
        return REBRICK_ERR_BAD_ARGUMENT;
    }
    rebrick_after_io_list_remove(tlssocket);
    rebrick_buffer_destroy(tlssocket->pending_read_list);
    rebrick_buffer_destroy(tlssocket->pending_write_list);
    rebrick_tls_ssl_destroy(tlssocket->tls);

    tlssocket->pending_read_list=NULL;
    tlssocket->pending_write_list=NULL;
    tlssocket->tls=NULL;

    if (tlssocket->override_after_connection_closed)
        tlssocket->override_after_connection_closed(tlssocket->override_callback_data);

    return REBRICK_SUCCESS;
}

static int32_t local_after_data_received_callback(void *callback_data, const struct sockaddr *addr, const char *buffer, size_t len)
{

    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;
    int32_t n;
    enum sslstatus status;
    rebrick_async_tlssocket_t *tlssocket = cast(callback_data, rebrick_async_tlssocket_t *);
    char buftemp[8192];
    if (!tlssocket)
    {

        rebrick_log_fatal("callback_data casting is null\n");
        return REBRICK_ERR_BAD_ARGUMENT;
    }
    printf("data received %zu \n",len);

    rebrick_buffer_t *readedbuffer = NULL;
    size_t tmp_len = len;
    while (tmp_len)
    {

        n = BIO_write(tlssocket->tls->read, buffer, tmp_len);
        if (n <= 0)
        {
            rebrick_log_fatal("ssl bio write failed\n");
            return REBRICK_ERR_TLS_ERR;
        }
        buffer += n;
        tmp_len -= n;

        result = check_ssl_init(tlssocket);

        if (result == REBRICK_ERR_TLS_INIT_NOT_FINISHED)
        {

            rebrick_buffer_destroy(readedbuffer);
            return result;
        }
        else if (result < 0)
        {

            rebrick_buffer_destroy(readedbuffer);
            call_after_connection(tlssocket,result);
            return result;
        }

        call_after_connection(tlssocket,result);



        do
        {

            n = SSL_read(tlssocket->tls->ssl, buftemp, sizeof(buftemp));

            if (n > 0)
            {

                //okunan byteları
                if (!readedbuffer)
                    rebrick_buffer_new(&readedbuffer, (uint8_t *)buftemp, (size_t)n,REBRICK_BUFFER_MALLOC_SIZE);
                else
                    rebrick_buffer_add(readedbuffer, (uint8_t *)buftemp, (size_t)n);
            }
        } while (n > 0);
        status = get_sslstatus(tlssocket->tls->ssl, n);
        if (status == SSLSTATUS_WANT_READ)
        {
            do
            {
                n = BIO_read(tlssocket->tls->write, buftemp, sizeof(buftemp));
                if (n > 0)
                {

                    if (tlssocket->pending_write_list)
                        result = rebrick_buffer_add(tlssocket->pending_write_list, (uint8_t *)buftemp, (size_t)n);
                    else
                        result = rebrick_buffer_new(&tlssocket->pending_write_list, (uint8_t *)buftemp, (size_t)n,REBRICK_BUFFER_MALLOC_SIZE);
                }
                else if (!BIO_should_retry(tlssocket->tls->write))
                {

                    rebrick_buffer_destroy(readedbuffer);
                    return REBRICK_ERR_TLS_ERR;
                }

            } while (n > 0);
        }
        if(status==SSLSTATUS_WANT_WRITE){

            rebrick_buffer_destroy(readedbuffer);
            return REBRICK_ERR_TLS_ERR;
        }
        if (status == SSLSTATUS_FAIL)
        {

            rebrick_buffer_destroy(readedbuffer);
            return REBRICK_ERR_TLS_ERR;
        }
    }

    if(tlssocket->override_after_data_received){
    size_t array_len;
    char *array;
    result = rebrick_buffer_to_array(readedbuffer, &array, &array_len);
    rebrick_buffer_destroy(readedbuffer);
    if(array)
    printf("%s\n",array);
    if (array_len)
        tlssocket->override_after_data_received(tlssocket->override_callback_data, addr, array, array_len);


    }else{
        rebrick_buffer_destroy(readedbuffer);
    }


    return REBRICK_SUCCESS;
}

int32_t local_after_data_sended_callback(void *callback_data, void *after_senddata, int status)
{

    char current_time_str[32] = {0};
    unused(current_time_str);

    rebrick_async_tlssocket_t *tlssocket = cast(callback_data, rebrick_async_tlssocket_t *);
    if (!tlssocket)
    {
        rebrick_log_fatal("callback_data casting is null\n");
        return REBRICK_ERR_BAD_ARGUMENT;
    }
    //burası önemli, flush_ssl_buffer yaptığımızda
    //create edilen char buffer silinmeli
    send_data_holder_t *holder = cast(after_senddata, send_data_holder_t *);

    if(status<0){//hata olmuş tekrar listeye eklenmeli
        if (!tlssocket->pending_write_list)
                    rebrick_buffer_new(&tlssocket->pending_write_list, (uint8_t *)holder->internal_data, (size_t)holder->internal_data_len,REBRICK_BUFFER_MALLOC_SIZE);
                else
                    rebrick_buffer_add(tlssocket->pending_write_list, (uint8_t *)holder->internal_data, (size_t)holder->internal_data_len);
        //flush_buffers(tlssocket);
    }

    if (holder && holder->internal_data)
        free(holder->internal_data);

    if (tlssocket->override_after_data_sended)
        tlssocket->override_after_data_sended(tlssocket->override_callback_data, holder ? holder->client_data : NULL, status);

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

int32_t rebrick_async_tlssocket_new(rebrick_async_tlssocket_t **socket, const rebrick_tls_context_t *tls_context, rebrick_sockaddr_t addr, void *callback_data,
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

    rebrick_async_tlssocket_t *tlssocket = new (rebrick_async_tlssocket_t);
    constructor(tlssocket, rebrick_async_tlssocket_t);
    tlssocket->override_after_connection_accepted = after_connection_accepted;
    tlssocket->override_after_connection_closed = after_connection_closed;
    tlssocket->override_after_data_received = after_data_received;
    tlssocket->override_after_data_sended = after_data_sended;
    tlssocket->override_callback_data = callback_data;
    tlssocket->tls_context = tls_context;
    //eğer burası çalışıyor ise ,
    //c ile inheritance yapılmış demektir.
    //function overloading de yapılmış olur.
    result = rebrick_async_tcpsocket_init(cast(tlssocket, struct rebrick_async_tcpsocket *), addr, tlssocket, local_after_connection_accepted_callback,
                                          local_after_connection_closed_callback, local_after_data_received_callback, local_after_data_sended_callback, backlog_or_isclient, local_create_client);
    if (result)
    {
        rebrick_log_fatal("tcpsocket create failed with result:%d\n", result);
        free(tlssocket);
        return result;
    }
    *socket = tlssocket;
    return REBRICK_SUCCESS;
}

int32_t rebrick_async_tlssocket_destroy(rebrick_async_tlssocket_t *socket)
{
    if (socket)
    {


        //buraya dikkat,burada çok kod yazmak lazım
        rebrick_async_tcpsocket_destroy(cast(socket, rebrick_async_tcpsocket_t *));


        //free(socket) yapmakmak lazım, zaten tcpsocket yapıyor
    }
    return REBRICK_SUCCESS;
}

int32_t rebrick_async_tlssocket_send(rebrick_async_tlssocket_t *socket, char *buffer, size_t len, void *aftersend_data)
{
    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;
    int32_t n;
    unused(result);
    char buftemp[8192*2];
    result=check_ssl_init(socket);
    if(result!=REBRICK_SUCCESS){

    return result;
    }


    int32_t writen_len=0;
    int32_t temp_len=len;
    while(writen_len<temp_len){
    n=SSL_write(socket->tls->ssl,(const void*)(buffer+writen_len),temp_len-writen_len);
    result= get_sslstatus(socket->tls->ssl,n);
    if(n>0){
        writen_len+=n;

         do
            {
                n = BIO_read(socket->tls->write, buftemp, sizeof(buftemp));
                if (n > 0)
                {

                    if (socket->pending_write_list)
                        result = rebrick_buffer_add(socket->pending_write_list, (uint8_t *)buftemp, (size_t)n);
                    else
                        result = rebrick_buffer_new(&socket->pending_write_list, (uint8_t *)buftemp, (size_t)n,REBRICK_BUFFER_MALLOC_SIZE);
                }
                else if (!BIO_should_retry(socket->tls->write))
                {


                    return REBRICK_ERR_TLS_ERR;
                }

            } while (n > 0);

    }
     if(result==SSLSTATUS_FAIL)
     return result;

    }
    flush_buffers(socket);

    if(socket->override_after_data_sended)
     socket->override_after_data_sended(socket->override_callback_data,aftersend_data,0);


    return REBRICK_SUCCESS;
}