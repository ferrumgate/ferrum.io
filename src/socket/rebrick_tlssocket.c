#include "rebrick_tlssocket.h"

/**
 * @brief client yada ssl olduğu için biz
 * içerden rebrick_tcpsocket_send yapıyoruz
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
    SSLSTATUS_CLOSED,
    SSLSTATUS_FAIL
};

static enum sslstatus get_sslstatus(SSL *ssl, int n)
{

    switch (SSL_get_error(ssl, n))
    {
    case SSL_ERROR_NONE:

        return SSLSTATUS_OK;
    case SSL_ERROR_WANT_WRITE:
        printf("ssl want write\n");
        return SSLSTATUS_WANT_WRITE;
    case SSL_ERROR_WANT_READ:

        return SSLSTATUS_WANT_READ;
    case SSL_ERROR_ZERO_RETURN:
        return SSLSTATUS_CLOSED;
    case SSL_ERROR_SYSCALL:
    default:
        return SSLSTATUS_FAIL;
    }
}
char sslerror[4096];
char *getOpenSSLError()
{
    BIO *bio = BIO_new(BIO_s_mem());
    ERR_print_errors(bio);
    char *buf;
    size_t len = BIO_get_mem_data(bio, &buf);
    size_t strlen = sizeof(sslerror);
    memset(sslerror, 0, strlen);
    memcpy(sslerror, buf, len < strlen ? len : (strlen - 1));
    BIO_free(bio);
    return sslerror;
}

static void clean_send_data_holder(void *ptr)
{
    send_data_holder_t *senddata = cast(ptr, send_data_holder_t *);
    if (senddata && senddata->internal_data)
        free(senddata->internal_data);
    if (senddata && senddata->client_data)
    {

        if (senddata->client_data->func)
            senddata->client_data->func(senddata->client_data->ptr);
        free(senddata->client_data);
    }
    if (senddata)
        free(senddata);
}

static int32_t flush_ssl_buffers(rebrick_tlssocket_t *tlssocket)
{
    uint8_t buftemp[BUF_SIZE] = {0};
    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;
    int32_t n;
    if (!tlssocket || !tlssocket->tls)
    {
        rebrick_log_fatal("socket tls is null\n");
        return REBRICK_ERR_BAD_ARGUMENT;
    }

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

            rebrick_clean_func_t cleanfunc = {.func = clean_send_data_holder, .ptr = holder};
            result = rebrick_tcpsocket_send(cast_to_tcp_socket(tlssocket), buftemp, n, cleanfunc);

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

    return REBRICK_SUCCESS;
}

static int32_t check_ssl_status(rebrick_tlssocket_t *tlssocket, int32_t n)
{
    char current_time_str[32] = {0};
    unused(current_time_str);
    // int32_t result;

    enum sslstatus status;
    // char buftemp[BUF_SIZE] = {0};
    if (!tlssocket || !tlssocket->tls)
    {
        rebrick_log_fatal("socket tls is null\n");
        return REBRICK_ERR_BAD_ARGUMENT;
    }

    status = get_sslstatus(tlssocket->tls->ssl, n);

    if (status == SSLSTATUS_WANT_READ)
    {
        rebrick_log_debug("ssl want read\n");
        n = flush_ssl_buffers(tlssocket);
        if (n < 0)
            return n;
    }
    if (status == SSLSTATUS_WANT_WRITE)
    {
        rebrick_log_debug("ssl want write\n");
        return REBRICK_ERR_TLS_ERR;
    }
    if (status == SSLSTATUS_CLOSED)
    {
        rebrick_log_error("ssl closed\n");
        return REBRICK_ERR_TLS_CLOSED;
    }
    if (status == SSLSTATUS_FAIL)
    {
        rebrick_log_error("ssl failed\n");
        return REBRICK_ERR_TLS_ERR;
    }

    if (!SSL_is_init_finished(tlssocket->tls->ssl))
        return REBRICK_ERR_TLS_INIT_NOT_FINISHED;
    return REBRICK_SUCCESS;
}

void flush_buffers(struct rebrick_tlssocket *tlssocket)
{

    char current_time_str[32] = {0};
    unused(current_time_str);
    uint8_t buftemp[BUF_SIZE];

    if (tlssocket && tlssocket->pending_write_list)
    {

        int32_t result;

        rebrick_log_debug("pending read list try to send\n");

        size_t len = 0;
        int32_t error_occured = 0;
        struct pending_data *el, *tmp;
        DL_FOREACH_SAFE(tlssocket->pending_write_list, el, tmp)
        {
            uint8_t *tmpbuffer = NULL;
            result = rebrick_buffers_to_array(el->data, &tmpbuffer, &len);
            int32_t writen_len = 0;
            int32_t temp_len = len;
            error_occured = 0;
            while (writen_len < temp_len)
            {
                int32_t n = SSL_write(tlssocket->tls->ssl, (const void *)(tmpbuffer + writen_len), temp_len - writen_len);
                result = check_ssl_status(tlssocket, n);

                if (result == REBRICK_ERR_TLS_ERR || result == REBRICK_ERR_TLS_CLOSED)
                {
                    rebrick_log_error("tls failed with %d\n", result);

                    error_occured = 1;
                    free(tmpbuffer);
                    if (tlssocket->on_error_occured)
                        tlssocket->on_error_occured(cast_to_base_socket(tlssocket), tlssocket->override_callback_data, result);

                    break;
                }
                else if (result != REBRICK_SUCCESS)
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

                            rebrick_clean_func_t cleanfunc = {.func = clean_send_data_holder, .ptr = holder};
                            //client datası olduğunu belirtmek için source 1 yapılıyor
                            cleanfunc.anydata.source = 1;
                            result = rebrick_tcpsocket_send(cast_to_tcp_socket(tlssocket), buftemp, n, cleanfunc);
                            if (result < 0)
                            {
                                free(holder);
                                free(tmpbuffer);
                            }
                            rebrick_buffers_destroy(el->data);

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
static int32_t ssl_handshake(rebrick_tlssocket_t *tlssocket)
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

        if (tlssocket->is_server)
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

static void local_on_error_occured_callback(rebrick_socket_t *socket, void *callbackdata, int32_t error)
{
    char current_time_str[32] = {0};
    unused(current_time_str);
    unused(error);
    unused(callbackdata);
    rebrick_tlssocket_t *tlssocket = cast_to_tls_socket(socket);

    if (tlssocket && tlssocket->override_on_error_occured)
        tlssocket->override_on_error_occured(cast_to_base_socket(tlssocket), tlssocket->override_callback_data, error);
}

#define call_after_connection(tlsserver, tlsclient)                                                                                                           \
    if (tlsserver && tlsclient && !tlsclient->called_override_after_connection_accepted && tlsclient->override_on_connection_accepted)                        \
    {                                                                                                                                                         \
        tlsclient->called_override_after_connection_accepted++;                                                                                               \
        tlsclient->override_on_connection_accepted(cast_to_base_socket(tlsserver), tlsclient->override_callback_data, &tlsclient->bind_addr.base, tlsclient); \
    }

static void local_on_connection_accepted_callback(rebrick_socket_t *serversocket, void *callback_data, const struct sockaddr *addr, void *client_handle)
{

    char current_time_str[32] = {0};
    unused(current_time_str);
    unused(addr);
    unused(callback_data);
    int32_t result;

    rebrick_tlssocket_t *tlsserver = cast_to_tls_socket(serversocket);

    if (!tlsserver)
    {
        rebrick_log_fatal("callback_data casting is null\n");
        return;
    }

    rebrick_tlssocket_t *tlsclient = NULL;
    //server ise client_handle yeni handle'dır yoksa, server handle ile aynıdır
    if (tlsserver->is_server)
        tlsclient = cast_to_tls_socket(client_handle);
    else
        tlsclient = tlsserver;

    //bağlandığında client yada server-client için yeni bir ssl oluşturulur
    rebrick_tls_ssl_t *tls_ssl;
    if (tlsserver->is_server && strlen(tlsserver->sni_pattern_or_name))
        result = rebrick_tls_ssl_new2(&tls_ssl, tlsserver->sni_pattern_or_name);
    else
    if (!tlsserver->is_server && strlen(tlsserver->sni_pattern_or_name))
        result=rebrick_tls_ssl_new3(&tls_ssl,tlsserver->tls_context,tlsserver->sni_pattern_or_name);
    else result = rebrick_tls_ssl_new(&tls_ssl, tlsserver->tls_context);

    if (result)
    {
        if (tlsserver->is_server)
            rebrick_tlssocket_destroy(tlsclient);
        client_handle = NULL;
        rebrick_log_fatal("ssl new failed for %s\n", tlsserver->tls_context->key);
        if (tlsserver->override_on_error_occured)
            tlsserver->override_on_error_occured(cast_to_base_socket(tlsserver), tlsserver->override_callback_data, result);
        return;
    }

    //base sınıfta olmayan kısımlar burada implemente edilmeli
    tlsclient->tls_context = tlsserver->tls_context;
    tlsclient->tls = tls_ssl;
    //burası sni çözmek için lazım
    tlsclient->tls->ref = tlsclient;
    //valgrind overlap diyor
    if (tlsclient != tlsserver)
        strncpy(tlsclient->sni_pattern_or_name, tlsserver->sni_pattern_or_name, REBRICK_TLS_SNI_MAX_LEN - 1);
    tlsclient->override_on_connection_accepted = tlsserver->override_on_connection_accepted;
    tlsclient->override_on_connection_closed = tlsserver->override_on_connection_closed;
    tlsclient->override_on_data_received = tlsserver->override_on_data_received;
    tlsclient->override_on_data_sended = tlsserver->override_on_data_sended;
    tlsclient->override_on_error_occured = tlsserver->override_on_error_occured;
    tlsclient->override_callback_data = tlsserver->override_callback_data;
    //tlsclient için callback_data kendisi geçilir.
    tlsclient->callback_data = tlsclient;

    int32_t status = ssl_handshake(tlsclient);

    if (status)
    {

        if (status == REBRICK_ERR_BAD_ARGUMENT)
        {
            if (tlsserver->is_server)
                rebrick_tlssocket_destroy(tlsclient);
            client_handle = NULL;
            rebrick_log_fatal("connection accepted failed with error:%d\n", status);
            if (tlsserver->override_on_error_occured)
                tlsserver->override_on_error_occured(cast_to_base_socket(tlsserver), tlsserver->override_callback_data, status);
            return;
        }
        status = check_ssl_status(tlsclient, status);
        if (status == REBRICK_SUCCESS || status == REBRICK_ERR_TLS_INIT_NOT_FINISHED)
        {
            //ssl problemi yok ise, her loop sonrası çalışacak kod ekleniyor
            //rebrick_after_io_list_add(flush_buffers, tlsclient);
        }
        else
        {
            //null koruması var
            //burası nasıl silinmeli acaba
            if (tlsserver->is_server)
                rebrick_tlssocket_destroy(tlsclient);
            client_handle = NULL;
            status = REBRICK_ERR_TLS_INIT;
            rebrick_log_fatal("connection accepted failed with error:%d\n", status);
            if (tlsserver->override_on_error_occured)
                tlsserver->override_on_error_occured(cast_to_base_socket(tlsserver), tlsserver->override_callback_data, status);
            return;
        }

        //this function triggers, if tls client is successfully connected

        call_after_connection(tlsserver, tlsclient);
    }
}

static void local_on_connection_closed_callback(rebrick_socket_t *socket, void *callback_data)
{

    char current_time_str[32] = {0};
    unused(current_time_str);
    unused(callback_data);
    rebrick_tlssocket_t *tlssocket = cast_to_tls_socket(socket);

    if (!tlssocket)
    {
        rebrick_log_fatal("callback_data casting is null\n");
        return;
    }
    rebrick_after_io_list_remove(tlssocket);

    rebrick_tls_ssl_destroy(tlssocket->tls);

    tlssocket->tls = NULL;

    pending_data_t *el, *tmp;
    DL_FOREACH_SAFE(tlssocket->pending_write_list, el, tmp)
    {
        rebrick_buffers_destroy(el->data);
        DL_DELETE(tlssocket->pending_write_list, el);
        rebrick_clean_func_t *deletedata = el->clean_func;
        free(el);
        if (deletedata)
        {
            if (deletedata->func)
            {

                deletedata->func(deletedata->ptr);
            }
            free(deletedata);
        }
    }

    if (tlssocket->override_on_connection_closed)
        tlssocket->override_on_connection_closed(cast_to_base_socket(tlssocket), tlssocket->override_callback_data);
}

static void local_after_data_received_callback(rebrick_socket_t *socket, void *callback_data, const struct sockaddr *addr, const uint8_t *buffer, ssize_t len)
{

    char current_time_str[32] = {0};
    unused(current_time_str);
    unused(callback_data);
    int32_t result;
    unused(result);
    int32_t n;
    int32_t status;

    rebrick_tlssocket_t *tlssocket = cast_to_tls_socket(socket);

    char buftemp[4096];
    if (!tlssocket)
    {
        rebrick_log_fatal("callback_data casting is null\n");
        return;
    }

    rebrick_buffers_t *readedbuffer = NULL;
    size_t tmp_len = len;
    while (tmp_len)
    {

        n = BIO_write(tlssocket->tls->read, buffer, tmp_len);
        if (n <= 0)
        {
            if (BIO_should_retry(tlssocket->tls->read))
            {
                continue;
            }
            rebrick_log_error("ssl bio write failed\n");
            rebrick_buffers_destroy(readedbuffer);
            if (tlssocket->override_on_error_occured)
                tlssocket->override_on_error_occured(cast_to_base_socket(tlssocket), tlssocket->override_callback_data, REBRICK_ERR_TLS_WRITE);
            return;
        }
        buffer += n;
        tmp_len -= n;

        do
        {

            n = SSL_read(tlssocket->tls->ssl, buftemp, sizeof(buftemp));

            if (n > 0)
            {

                //okunan byteları
                if (!readedbuffer)
                    rebrick_buffers_new(&readedbuffer, (uint8_t *)buftemp, (size_t)n, REBRICK_BUFFER_MALLOC_SIZE);
                else
                    rebrick_buffers_add(readedbuffer, (uint8_t *)buftemp, (size_t)n);
            }
        } while (n > 0);
        status = check_ssl_status(tlssocket, n);

        if (status == REBRICK_ERR_TLS_ERR || status == REBRICK_ERR_TLS_CLOSED)
        {

            rebrick_log_error("ssl status failed %d:%d\n", n, status);
            rebrick_buffers_destroy(readedbuffer);
            if (tlssocket->override_on_error_occured)
                tlssocket->override_on_error_occured(cast_to_base_socket(tlssocket), tlssocket->override_callback_data, status);

            return;
        }
    }

    if (tlssocket->override_on_data_received)
    {
        size_t array_len = 0;
        uint8_t *array;
        result = rebrick_buffers_to_array(readedbuffer, &array, &array_len);

        if (array_len)
        {
            tlssocket->override_on_data_received(cast_to_base_socket(tlssocket), tlssocket->override_callback_data, addr, array, array_len);
            free(array);
        }
    }

    rebrick_buffers_destroy(readedbuffer);

    flush_buffers(tlssocket);
}

static void local_on_data_sended_callback(rebrick_socket_t *socket, void *callback_data, void *source)
{

    char current_time_str[32] = {0};
    unused(current_time_str);
    unused(callback_data);

    rebrick_tlssocket_t *tlssocket = cast_to_tls_socket(socket);
    if (!tlssocket)
    {
        rebrick_log_fatal("callback_data casting is null\n");
        return;
    }

    //burası önemli, flush_ssl_buffer yaptığımızda

    //flush_buffers(tlssocket);

    if (source) //eğer gönderilen data client datası ise
        if (tlssocket->override_on_data_sended)
            tlssocket->override_on_data_sended(cast_to_base_socket(tlssocket), tlssocket->override_callback_data, NULL);
}

/**
 * @brief this function creates a new instance of current instance
 * this is function overloading
 * @return struct rebrick_tcpsocket*
 */
static struct rebrick_tcpsocket *local_create_client()
{
    char current_time_str[32] = {0};
    unused(current_time_str);
    rebrick_tlssocket_t *client = new (rebrick_tlssocket_t);
    constructor(client, rebrick_tlssocket_t);
    return cast_to_tcp_socket(client);
}

int32_t rebrick_tlssocket_init(rebrick_tlssocket_t *tlssocket,const char *sni_pattern_or_name, const rebrick_tls_context_t *tls_context, rebrick_sockaddr_t addr,
                                void *callback_data,int32_t backlog_or_isclient, rebrick_tcpsocket_create_client_t create_client,
                               rebrick_on_connection_accepted_callback_t on_connection_accepted,
                               rebrick_on_connection_closed_callback_t on_connection_closed,
                               rebrick_on_data_received_callback_t on_data_received,
                               rebrick_on_data_sended_callback_t on_data_sended,
                               rebrick_on_error_occured_callback_t on_error_occured)
{

    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;

    if (!tls_context)
    {
        rebrick_log_fatal("tls context is null\n");
        return REBRICK_ERR_BAD_ARGUMENT;
    }

    if (rebrick_tls_context_is_server(tls_context) && !backlog_or_isclient)
    {
        rebrick_log_fatal("tls context is server but backlog_or_isclient parameter is 0\n");
        return REBRICK_ERR_BAD_ARGUMENT;
    }
    if (!rebrick_tls_context_is_server(tls_context) && backlog_or_isclient)
    {
        rebrick_log_fatal("tls context is client but backlog_or_isclient parameter is server > 0\n");
        return REBRICK_ERR_BAD_ARGUMENT;
    }

    //burası sayesinde yeni bir
    if(sni_pattern_or_name)
    snprintf(tlssocket->sni_pattern_or_name, REBRICK_TLS_SNI_MAX_LEN, "%s", sni_pattern_or_name);


    tlssocket->is_server = backlog_or_isclient;

    tlssocket->override_on_connection_accepted = on_connection_accepted;
    tlssocket->override_on_connection_closed = on_connection_closed;
    tlssocket->override_on_data_received = on_data_received;
    tlssocket->override_on_data_sended = on_data_sended;
    tlssocket->override_callback_data = callback_data;
    tlssocket->override_on_error_occured = on_error_occured;
    tlssocket->tls_context = tls_context;



    //this is OOP inheritance with c
    //base class init function call.
    result = rebrick_tcpsocket_init(cast_to_tcp_socket(tlssocket), addr, tlssocket, backlog_or_isclient, create_client, local_on_connection_accepted_callback,
                                    local_on_connection_closed_callback, local_after_data_received_callback, local_on_data_sended_callback, local_on_error_occured_callback);
    if (result)
    {
        int32_t uv_err = HAS_UV_ERR(result) ? UV_ERR(result) : 0;
        rebrick_log_fatal("tcpsocket create failed with result:%d %s\n", result, uv_strerror(uv_err));
        return result;
    }

    //rebrick_tcpsocket_nodelay(cast_to_tcp_socket(tlssocket),1);

    return REBRICK_SUCCESS;
}

int32_t rebrick_tlssocket_new(rebrick_tlssocket_t **socket, const char *sni_pattern_or_name, rebrick_tls_context_t *tlscontext, rebrick_sockaddr_t addr,
                               void *callback_data,int32_t backlog_or_isclient,
                               rebrick_on_connection_accepted_callback_t on_connection_accepted,
                               rebrick_on_connection_closed_callback_t on_connection_closed,
                               rebrick_on_data_received_callback_t on_data_received,
                               rebrick_on_data_sended_callback_t on_data_sended,
                               rebrick_on_error_occured_callback_t on_error_occured)
{

    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;

     rebrick_tls_context_t *sni_context;
    //if tlscontext is null, use default SNI context
    if (tlscontext)
        sni_context = tlscontext;
    else
    {
        result = rebrick_tls_context_get(REBRICK_TLS_CONTEXT_SNI, &sni_context);
        if (result < 0)
        {
            rebrick_log_fatal("sni tls context not found\n");
            return result;
        }
    }

    rebrick_tlssocket_t *tlssocket = new (rebrick_tlssocket_t);
    constructor(tlssocket, rebrick_tlssocket_t);

    result = rebrick_tlssocket_init(tlssocket,sni_pattern_or_name, sni_context, addr, callback_data, backlog_or_isclient, local_create_client, on_connection_accepted, on_connection_closed, on_data_received, on_data_sended, on_error_occured);
    if (result < 0)
    {
        free(tlssocket);
        rebrick_log_error("tls socket init failed with:%d\n", result);
        return result;
    }


    *socket = tlssocket;
    return REBRICK_SUCCESS;
}

int32_t rebrick_tlssocket_destroy(rebrick_tlssocket_t *socket)
{
    char current_time_str[32] = {0};
    unused(current_time_str);

    if (socket)
    {
        //buraya başka kod yazmaya gerek yok
        if (socket->parent_socket)
        {
            int32_t result = SSL_shutdown(socket->tls->ssl);
            check_ssl_status(socket, result);
        }
        else
        {
            rebrick_tcpsocket_t *el, *tmp;
            DL_FOREACH_SAFE(socket->clients, el, tmp)
            {
                rebrick_tlssocket_t *tsocket = cast_to_tls_socket(el);
                int32_t result = SSL_shutdown(tsocket->tls->ssl);
                check_ssl_status(tsocket, result);
            }
        }
        rebrick_tcpsocket_destroy(cast_to_tcp_socket(socket));

        //free(socket) yapmakmak lazım, zaten tcpsocket yapıyor
    }
    return REBRICK_SUCCESS;
}

int32_t rebrick_tlssocket_send(rebrick_tlssocket_t *socket, uint8_t *buffer, size_t len, rebrick_clean_func_t cleanfuncs)
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

    rebrick_buffers_t *buffertmp = NULL;
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
                        rebrick_buffers_new(&buffertmp, (uint8_t *)buftemp, (size_t)n, REBRICK_BUFFER_MALLOC_SIZE);
                    else
                        rebrick_buffers_add(buffertmp, (uint8_t *)buftemp, (size_t)n);
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
            rebrick_buffers_new(&data->data, (uint8_t *)(buffer + writen_len), (size_t)(temp_len - writen_len), REBRICK_BUFFER_MALLOC_SIZE);

            rebrick_clean_func_clone(&cleanfuncs, data->clean_func);

            DL_APPEND(socket->pending_write_list, data);
            break;
        }
        else if (result == REBRICK_ERR_TLS_ERR || result == REBRICK_ERR_TLS_CLOSED)
        {
            rebrick_log_error("tls failed\n");
            rebrick_buffers_destroy(buffertmp);
            return result;
        }
    }
    result = REBRICK_SUCCESS;
    if (buffertmp)
    {
        uint8_t *tmpbuffer = NULL;
        size_t tmplen = 0;
        rebrick_buffers_to_array(buffertmp, &tmpbuffer, &tmplen);
        if (tmplen)
        {
            send_data_holder_t *holder = new (send_data_holder_t);
            constructor(holder, send_data_holder_t);
            holder->internal_data = tmpbuffer;
            holder->internal_data_len = len;
            rebrick_clean_func_clone(&cleanfuncs, holder->client_data);

            rebrick_clean_func_t cleanfunc = {.func = clean_send_data_holder, .ptr = holder};
            //client datası olduğunu belirtmek için source 1 yapılıyor
            cleanfunc.anydata.source = 1;
            result = rebrick_tcpsocket_send(cast_to_tcp_socket(socket), tmpbuffer, tmplen, cleanfunc);
            if (result < 0)
            {
                free(holder);
                free(tmpbuffer);
            }
        }
        rebrick_buffers_destroy(buffertmp);
    }

    //flush_buffers(socket);

    return result;
}

int32_t rebrick_tlssocket_change_context(rebrick_tlssocket_t *socket, const char *servername)
{
    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;
    unused(result);
    if (!socket || !servername)
    {
        rebrick_log_error("socket or servername is null\n");
        return REBRICK_ERR_BAD_ARGUMENT;
    }

    rebrick_tls_context_t *context;
    result = rebrick_tls_context_get(servername, &context);
    if (result < 0)
    {
        rebrick_log_error("error at finding context for servername:%s\n ", servername);
        return result;
    }
    strncpy(socket->sni, servername, REBRICK_TLS_SNI_MAX_LEN - 1);
    socket->tls_context = context;
    SSL_set_SSL_CTX(socket->tls->ssl, context->tls_ctx);
    return REBRICK_SUCCESS;
}