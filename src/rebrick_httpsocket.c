#include "rebrick_async_httpsocket.h"

#define REBRICK_HTTP_BUFFER_MALLOC 8192

int32_t rebrick_http_key_value_new(rebrick_http_key_value_t **keyvalue, const char *key, const char *value)
{
    char current_time_str[32] = {0};
    unused(current_time_str);
    size_t keylen = 0;
    if (key)
        keylen = strlen(key);
    size_t valuelen = 0;
    if (value)
        valuelen = strlen(value);
    rebrick_http_key_value_t *tmp = malloc(sizeof(rebrick_http_key_value_t));
    if_is_null_then_die(tmp, "malloc problem\n");
    memset(tmp, 0, sizeof(rebrick_http_key_value_t));
    tmp->key = malloc(keylen + 1);
    if_is_null_then_die(tmp->key, "malloc problem\n");
    memset(tmp->key, 0, keylen + 1);
    if (key)
        memcpy(tmp->key, key, keylen);
    tmp->value = malloc(valuelen + 1);
    if_is_null_then_die(tmp->value, "malloc problem\n");
    memset(tmp->value, 0, valuelen + 1);
    if (value)
        memcpy(tmp->value, value, valuelen);
    tmp->keylen = keylen + 1;
    tmp->valuelen = valuelen + 1;
    *keyvalue = tmp;

    return REBRICK_SUCCESS;
}

int32_t rebrick_http_key_value_new2(rebrick_http_key_value_t **keyvalue, const void *key, size_t keylen, const void *value, size_t valuelen)
{
    char current_time_str[32] = {0};
    unused(current_time_str);

    rebrick_http_key_value_t *tmp = malloc(sizeof(rebrick_http_key_value_t));
    if_is_null_then_die(tmp, "malloc problem\n");
    memset(tmp, 0, sizeof(rebrick_http_key_value_t));
    tmp->key = malloc(keylen);
    if_is_null_then_die(tmp->key, "malloc problem\n");
    memset(tmp->key, 0, keylen);
    if (key)
        memcpy(tmp->key, key, keylen);
    tmp->value = malloc(valuelen + 1);
    if_is_null_then_die(tmp->value, "malloc problem\n");
    memset(tmp->value, 0, valuelen + 1);
    if (value)
        memcpy(tmp->value, value, valuelen);
    tmp->keylen = keylen;
    tmp->valuelen = valuelen;
    *keyvalue = tmp;

    return REBRICK_SUCCESS;
}

int32_t rebrick_http_key_value_destroy(rebrick_http_key_value_t *keyvalue)
{
    if (keyvalue)
    {
        if (keyvalue->key)
            free(keyvalue->key);

        if (keyvalue->value)
            free(keyvalue->value);
        free(keyvalue);
    }
    return REBRICK_SUCCESS;
}

int32_t rebrick_http_header_new(rebrick_http_header_t **header, const char *path, const char *method, int32_t major_version)
{

    return rebrick_http_header_new2(header, path, method, major_version, major_version == REBRICK_HTTP_VERSION1 ? 1 : 0);
}
int32_t rebrick_http_header_new2(rebrick_http_header_t **header, const char *path, const char *method, int8_t major, int8_t minor)
{
    char current_time_str[32] = {0};
    unused(current_time_str);

    rebrick_http_header_t *tmp = new (rebrick_http_header_t);
    constructor(tmp, rebrick_http_header_t);
    if (path)
    {
        size_t path_len = strlen(path);
        if (path_len > REBRICK_HTTP_MAX_PATH_LEN - 1)
            return REBRICK_ERR_BAD_ARGUMENT;
        strcpy(tmp->path, path);
    }
    if (method)
    {
        size_t method_len = strlen(method);
        if (method_len > REBRICK_HTTP_MAX_METHOD_LEN - 1)
            return REBRICK_ERR_BAD_ARGUMENT;
        strcpy(tmp->method, method);
    }
    tmp->major_version = major;
    tmp->minor_version = minor;

    *header = tmp;
    return REBRICK_SUCCESS;
}

int32_t rebrick_http_header_add_header(rebrick_http_header_t *header, const char *key, const char *value)
{
    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;
    if (!header || !key || !value)
        return REBRICK_ERR_BAD_ARGUMENT;
    rebrick_http_key_value_t *keyvalue;
    result = rebrick_http_key_value_new(&keyvalue, key, value);
    if (result)
        return result;
    HASH_ADD_STR(header->headers, key, keyvalue);
    return REBRICK_SUCCESS;
}
int32_t rebrick_http_header_contains_key(rebrick_http_header_t *header, const char *key, int32_t *founded)
{
    if (!header || !key)
        return REBRICK_ERR_BAD_ARGUMENT;
    rebrick_http_key_value_t *keyvalue;
    HASH_FIND_STR(header->headers, key, keyvalue);
    *founded = FALSE;
    if (keyvalue)
        *founded = TRUE;
    return REBRICK_SUCCESS;
}
int32_t rebrick_http_header_remove_key(rebrick_http_header_t *header, const char *key)
{
    if (!header || !key)
        return REBRICK_ERR_BAD_ARGUMENT;
    rebrick_http_key_value_t *keyvalue;
    HASH_FIND_STR(header->headers, key, keyvalue);
    if (keyvalue)
    {
        HASH_DEL(header->headers, keyvalue);
        rebrick_http_key_value_destroy(keyvalue);
    }
    return REBRICK_SUCCESS;
}
int32_t rebrick_http_header_destroy(rebrick_http_header_t *header)
{
    char current_time_str[32] = {0};
    unused(current_time_str);
    if (header)
    {
        rebrick_http_key_value_t *s, *tmp;
        HASH_ITER(hh, header->headers, s, tmp)
        {
            HASH_DEL(header->headers, s);
            rebrick_http_key_value_destroy(s);
        }
        free(header);
    }
    return REBRICK_SUCCESS;
}

int32_t rebrick_http_header_to_buffer(rebrick_http_header_t *header, rebrick_buffer_t **rbuffer)
{
    char current_time_str[32] = {0};
    unused(current_time_str);
    if (!header)
        return REBRICK_ERR_BAD_ARGUMENT;

    char buffer[REBRICK_HTTP_MAX_HEADER_LEN];
    int32_t written_chars_count = 0;

    if (header->path[0])
    written_chars_count=snprintf(buffer,REBRICK_HTTP_MAX_HEADER_LEN,"%s %s HTTP/%d.%d\r\n",(header->method?header->method:"GET"),header->path,header->major_version,header->minor_version);
    else
        written_chars_count = snprintf(buffer, REBRICK_HTTP_MAX_HEADER_LEN, "HTTP/%d.%d %d %s\r\n", header->major_version, header->minor_version, header->status_code, header->status_code_str);
    if (written_chars_count == REBRICK_HTTP_MAX_HEADER_LEN - 1)
    {
        rebrick_log_error("max http header len\n");
        return REBRICK_ERR_LEN_NOT_ENOUGH;
    }

    rebrick_http_key_value_t *s, *tmp;
    HASH_ITER(hh, header->headers, s, tmp)
    {

        written_chars_count += snprintf(buffer + written_chars_count, REBRICK_HTTP_MAX_HEADER_LEN - written_chars_count, "%s:%s\r\n", s->key, s->value);
        if (written_chars_count == REBRICK_HTTP_MAX_HEADER_LEN - 1)
        {
            rebrick_log_error("max http header len\n");
            return REBRICK_ERR_LEN_NOT_ENOUGH;
        }
    }
    written_chars_count += snprintf(buffer + written_chars_count, REBRICK_HTTP_MAX_HEADER_LEN - written_chars_count, "\r\n");
    if (written_chars_count == REBRICK_HTTP_MAX_HEADER_LEN - 1)
    {
        rebrick_log_error("max http header len\n");
        return REBRICK_ERR_LEN_NOT_ENOUGH;
    }

    rebrick_buffer_t *rtmp;
    int32_t result = rebrick_buffer_new(&rtmp, cast(buffer,uint8_t*), written_chars_count, REBRICK_HTTP_MAX_HEADER_LEN);
    if (result < 0)
        return result;

    *rbuffer = rtmp;

    return REBRICK_SUCCESS;
}

static int32_t local_on_error_occured_callback(rebrick_async_socket_t *socket, void *callbackdata, int error)
{
    unused(socket);
    unused(callbackdata);
    unused(error);
    return REBRICK_SUCCESS;
}

static int32_t local_on_connection_accepted_callback(rebrick_async_socket_t *serversocket, void *callback_data, const struct sockaddr *addr, void *client_handle, int status)
{

    unused(serversocket);
    unused(callback_data);
    unused(addr);
    unused(client_handle);
    unused(status);
    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;
    unused(result);

    rebrick_async_httpsocket_t *httpsocket = cast(serversocket, rebrick_async_httpsocket_t *);
    if (httpsocket)
    {
        if (httpsocket->override_override_on_connection_accepted)
            httpsocket->override_override_on_connection_accepted(cast_to_base_socket(httpsocket), httpsocket->override_override_callback_data, addr, client_handle, status);
    }

    return REBRICK_SUCCESS;
}

static int32_t local_on_connection_closed_callback(rebrick_async_socket_t *serversocket, void *callback_data)
{
    unused(serversocket);
    unused(callback_data);
    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;
    unused(result);

    rebrick_async_httpsocket_t *httpsocket = cast(serversocket, rebrick_async_httpsocket_t *);

    if (httpsocket)
    {

        if (httpsocket->header)
        {
            rebrick_http_header_destroy(httpsocket->header);
        }

        if (httpsocket->override_override_on_connection_closed)
            httpsocket->override_override_on_connection_closed(serversocket, httpsocket->override_override_callback_data);
    }

    return REBRICK_SUCCESS;
}

static int32_t local_on_data_sended_callback(rebrick_async_socket_t *socket, void *callback_data, void *source, int status)
{
    unused(socket);
    unused(callback_data);
    unused(source);
    unused(status);
    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;
    unused(result);

    return REBRICK_SUCCESS;
}

#define call_on_error(httpsocket, error)                                                                                                     \
    if (httpsocket->override_override_on_error_occured)                                                                                      \
    {                                                                                                                                        \
        httpsocket->override_override_on_error_occured(cast_to_base_socket(httpsocket), httpsocket->override_override_callback_data, error); \
    }

static int32_t local_after_data_received_callback(rebrick_async_socket_t *socket, void *callback_data, const struct sockaddr *addr, const char *buffer, ssize_t len)
{
    unused(socket);
    unused(callback_data);
    unused(addr);
    unused(buffer);
    unused(len);
    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;
    unused(result);

    if (!socket)
        return REBRICK_ERR_BAD_ARGUMENT;

    rebrick_async_httpsocket_t *httpsocket = cast_to_http_socket(socket);

    if (httpsocket->override_override_on_data_received)
        httpsocket->override_override_on_data_received(cast_to_base_socket(httpsocket), httpsocket->override_override_callback_data, addr, buffer, len);

    if (httpsocket->is_header_parsed)
    {
        if (httpsocket->on_http_body_received)
        {
            httpsocket->on_http_body_received(cast_to_base_socket(httpsocket), httpsocket->override_override_callback_data, addr,
                                              buffer, len);
        }
    }
    else
    {
        size_t prevbuflen = 0;
        if (httpsocket->tmp_buffer)
        {
            result = rebrick_buffer_add(httpsocket->tmp_buffer, cast(buffer, uint8_t *), len);
            prevbuflen = httpsocket->tmp_buffer->len;
        }
        else
        {
            result = rebrick_buffer_new(&httpsocket->tmp_buffer, cast(buffer, uint8_t *), len, REBRICK_HTTP_BUFFER_MALLOC);
        }

        if (result < 0)
        {

            call_on_error(httpsocket, result);
            return result;
        }
        if (!httpsocket->header)
        {
            httpsocket->header = new (rebrick_http_header_t);
            constructor(httpsocket->header, rebrick_http_header_t);
            httpsocket->header->major_version = 1;
        }

        httpsocket->parsing_params.num_headers = sizeof(httpsocket->parsing_params.headers) / sizeof(httpsocket->parsing_params.headers[0]);
        ssize_t pret = phr_parse_request(cast(httpsocket->tmp_buffer->buf, const char *),
                                         httpsocket->tmp_buffer->len,
                                         cast(&httpsocket->parsing_params.method, const char **), &httpsocket->parsing_params.method_len,
                                         cast(&httpsocket->parsing_params.path, const char **), &httpsocket->parsing_params.path_len,
                                         &httpsocket->parsing_params.minor_version,
                                         httpsocket->parsing_params.headers, &httpsocket->parsing_params.num_headers, prevbuflen);
        if (pret == -1)
        {
            call_on_error(httpsocket, REBRICK_ERR_HTTP_HEADER_PARSE);
            return REBRICK_ERR_HTTP_HEADER_PARSE;
        }
        if (httpsocket->tmp_buffer->len >= REBRICK_HTTP_MAX_HEADER_LEN)
        {
            call_on_error(httpsocket, REBRICK_HTTP_MAX_HEADER_LEN);
            return REBRICK_ERR_LEN_NOT_ENOUGH;
        }
        if (pret > 0)
        {
            memcpy(httpsocket->header->method, httpsocket->parsing_params.method, httpsocket->parsing_params.method_len);
            memcpy(httpsocket->header->path, httpsocket->parsing_params.path, httpsocket->parsing_params.path_len);
            for (size_t i = 0; i < httpsocket->parsing_params.num_headers; ++i)
            {
                struct phr_header *header = httpsocket->parsing_params.headers + i;
                rebrick_http_key_value_t *keyvalue;
                result = rebrick_http_key_value_new2(&keyvalue, header->name, header->name_len, header->value, header->value_len);
                if (result < 0)
                {
                    //TODO burayı yazalım
                }
                //burayı yazalım
                HASH_ADD_STR(httpsocket->header->headers, key, keyvalue);
            }
            httpsocket->is_header_parsed = TRUE;
            httpsocket->header_len = pret;

            //http header finished
            if (httpsocket->on_http_header_received)
                httpsocket->on_http_header_received(cast_to_base_socket(httpsocket), httpsocket->override_override_callback_data, httpsocket->header, REBRICK_SUCCESS);
            //if there is data after header parsed in buffer
            //call on_http_body
            if (cast(httpsocket->tmp_buffer->len, ssize_t) > pret)
            {
                if (httpsocket->on_http_body_received)
                {
                    size_t length_remain = httpsocket->tmp_buffer->len - pret;
                    size_t offset = httpsocket->tmp_buffer->len - length_remain;
                    httpsocket->on_http_body_received(cast_to_base_socket(httpsocket), httpsocket->override_override_callback_data, addr,
                                                      cast(httpsocket->tmp_buffer->buf + offset, char *), length_remain);
                }
            }
        }
    }

    return REBRICK_SUCCESS;
}

static struct rebrick_async_tcpsocket *local_create_client()
{
    char current_time_str[32] = {0};
    unused(current_time_str);
    rebrick_async_httpsocket_t *client = new (rebrick_async_httpsocket_t);
    constructor(client, rebrick_async_httpsocket_t);
    return cast(client, rebrick_async_tcpsocket_t *);
}

int32_t rebrick_async_httpsocket_init(rebrick_async_httpsocket_t *httpsocket, rebrick_tls_context_t *tls_context, rebrick_sockaddr_t addr, void *callback_data,
                                      rebrick_on_connection_accepted_callback_t on_connection_accepted,
                                      rebrick_on_connection_closed_callback_t on_connection_closed,
                                      rebrick_on_data_received_callback_t on_data_received,
                                      rebrick_on_data_sended_callback_t on_data_sended,
                                      rebrick_on_error_occured_callback_t on_error_occured, int32_t backlog_or_isclient,
                                      rebrick_on_http_header_received_callback_t on_http_header_received,
                                      rebrick_on_http_body_received_callback_t on_http_body_received, rebrick_async_tcpsocket_create_client_t create_client)

{
    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;
    unused(result);
    httpsocket->override_override_tls_context = tls_context;
    if (tls_context)
    {
        result = rebrick_async_tlssocket_init(cast_to_tls_socket(httpsocket), tls_context, addr, NULL, local_on_connection_accepted_callback, local_on_connection_closed_callback, local_after_data_received_callback, local_on_data_sended_callback, local_on_error_occured_callback, backlog_or_isclient, create_client);
    }
    else
    {
        result = rebrick_async_tcpsocket_init(cast_to_tcp_socket(httpsocket), addr, NULL, local_on_connection_accepted_callback, local_on_connection_closed_callback, local_after_data_received_callback, local_on_data_sended_callback, local_on_error_occured_callback, backlog_or_isclient, create_client);
    }
    if (result < 0)
    {
        rebrick_log_error("http socket creation failed with eror:%d\n", result);

        return result;
    }
    httpsocket->override_override_on_connection_accepted = on_connection_accepted;
    httpsocket->override_override_on_connection_closed = on_connection_closed;
    httpsocket->override_override_on_data_received = on_data_received;
    httpsocket->override_override_on_data_sended = on_data_sended;
    httpsocket->override_override_on_error_occured = on_error_occured;
    httpsocket->override_override_callback_data = callback_data;
    httpsocket->on_http_header_received = on_http_header_received;
    httpsocket->on_http_body_received = on_http_body_received;

    return REBRICK_SUCCESS;
}

int32_t rebrick_async_httpsocket_new(rebrick_async_httpsocket_t **socket, rebrick_tls_context_t *tls_context, rebrick_sockaddr_t addr, void *callback_data,
                                     rebrick_on_connection_accepted_callback_t on_connection_accepted,
                                     rebrick_on_connection_closed_callback_t on_connection_closed,
                                     rebrick_on_data_received_callback_t on_data_received,
                                     rebrick_on_data_sended_callback_t on_data_sended,
                                     rebrick_on_error_occured_callback_t on_error_occured, int32_t backlog_or_isclient,
                                     rebrick_on_http_header_received_callback_t on_http_header_received,
                                     rebrick_on_http_body_received_callback_t on_http_body_received)
{

    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;
    unused(result);
    rebrick_async_httpsocket_t *httpsocket = new (rebrick_async_httpsocket_t);
    constructor(httpsocket, rebrick_async_httpsocket_t);

    result = rebrick_async_httpsocket_init(httpsocket, tls_context, addr,
                                           callback_data, on_connection_accepted, on_connection_closed, on_data_received, on_data_sended, on_error_occured, backlog_or_isclient,
                                           on_http_header_received, on_http_body_received, local_create_client);
    if (result < 0)
    {
        rebrick_log_error("http socket init failed with error:%d\n", result);
        free(httpsocket);
        return result;
    }
    *socket = httpsocket;
    return REBRICK_SUCCESS;
}

int32_t rebrick_async_httpsocket_destroy(rebrick_async_httpsocket_t *socket)
{
    unused(socket);
    if (socket)
    {
        if (socket->override_override_tls_context)
        {
            rebrick_async_tlssocket_destroy(cast_to_tls_socket(socket));
        }
        else
        {
            rebrick_async_tcpsocket_destroy(cast_to_tcp_socket(socket));
        }
    }
    return REBRICK_SUCCESS;
}
int32_t rebrick_async_httpsocket_send(rebrick_async_httpsocket_t *socket, char *buffer, size_t len, rebrick_clean_func_t cleanfunc)
{
    unused(socket);
    unused(buffer);
    unused(len);
    unused(cleanfunc);
    if (!socket || !buffer)
        return REBRICK_ERR_BAD_ARGUMENT;

    return REBRICK_SUCCESS;
}