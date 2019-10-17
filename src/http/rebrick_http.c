#include "rebrick_http.h"



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

    tmp->key_lower=malloc(keylen+1);
    if_is_null_then_die(tmp->key_lower,"malloc problem\n");
    memset(tmp->key_lower,0,keylen+1);

    if(key){
        size_t index=0;
        while(index<keylen){
            *(tmp->key_lower+index)=tolower(*((char*)key+index));
            index++;
        }
    }



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

int32_t rebrick_http_key_value_new2(rebrick_http_key_value_t **keyvalue, const void *key, size_t keylen, const void *value, size_t valuelen)
{
    char current_time_str[32] = {0};
    unused(current_time_str);

    rebrick_http_key_value_t *tmp = malloc(sizeof(rebrick_http_key_value_t));
    if_is_null_then_die(tmp, "malloc problem\n");
    memset(tmp, 0, sizeof(rebrick_http_key_value_t));
    tmp->key = malloc(keylen+1);
    if_is_null_then_die(tmp->key, "malloc problem\n");
    memset(tmp->key, 0, keylen+1);
    if (key)
        memcpy(tmp->key, key, keylen);

    tmp->key_lower=malloc(keylen+1);
    if_is_null_then_die(tmp->key_lower,"malloc problem\n");
    memset(tmp->key_lower,0,keylen+1);

    if(key){
        size_t index=0;
        while(index<keylen){
            *(tmp->key_lower+index)=tolower(*((char*)key+index));
            index++;
        }
    }

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

        if(keyvalue->key_lower)
        free(keyvalue->key_lower);

        if (keyvalue->value)
            free(keyvalue->value);
        free(keyvalue);
    }
    return REBRICK_SUCCESS;
}


int32_t rebrick_http_header_new(rebrick_http_header_t **header,const char *scheme,const char*host, const char *method, const char *path, int8_t major, int8_t minor)
{
    char current_time_str[32] = {0};
    unused(current_time_str);

    rebrick_http_header_t *tmp = new (rebrick_http_header_t);
    constructor(tmp, rebrick_http_header_t);
    if(scheme){
        size_t scheme_len = strlen(scheme);
        if (scheme_len > REBRICK_HTTP_MAX_SCHEME_LEN - 1)
            return REBRICK_ERR_BAD_ARGUMENT;
        strcpy(tmp->scheme, scheme);
    }
    if(host){
         size_t host_len = strlen(host);
        if (host_len > REBRICK_HTTP_MAX_HOSTNAME_LEN - 1)
            return REBRICK_ERR_BAD_ARGUMENT;
        strcpy(tmp->host, host);
    }
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
    tmp->is_request=TRUE;
    tmp->major_version = major;
    tmp->minor_version = minor;

    *header = tmp;
    return REBRICK_SUCCESS;
}


int32_t rebrick_http_header_new2(rebrick_http_header_t **header,const char *scheme,size_t scheme_len,const char*host,size_t host_len,const void *method,size_t method_len,const void *path,size_t path_len,int8_t major,int8_t minor){
     char current_time_str[32] = {0};
    unused(current_time_str);

    rebrick_http_header_t *tmp = new (rebrick_http_header_t);
    constructor(tmp, rebrick_http_header_t);
    if(scheme){
        if(scheme_len > REBRICK_HTTP_MAX_SCHEME_LEN-1)
        return REBRICK_ERR_BAD_ARGUMENT;
        memcpy(tmp->scheme,scheme,scheme_len);
    }
    if(host){
        if(host_len > REBRICK_HTTP_MAX_HOSTNAME_LEN-1)
        return REBRICK_ERR_BAD_ARGUMENT;
        memcpy(tmp->host,host,host_len);
    }
    if (path)
    {

        if (path_len > REBRICK_HTTP_MAX_PATH_LEN - 1)
            return REBRICK_ERR_BAD_ARGUMENT;
        memcpy(tmp->path, path,path_len);
    }
    if (method)
    {

        if (method_len > REBRICK_HTTP_MAX_METHOD_LEN - 1)
            return REBRICK_ERR_BAD_ARGUMENT;
        memcpy(tmp->method, method,method_len);

    }
    tmp->is_request=TRUE;
    tmp->major_version = major;
    tmp->minor_version = minor;

    *header = tmp;
    return REBRICK_SUCCESS;
}
int32_t rebrick_http_header_new3(rebrick_http_header_t **header,int32_t status,const char *status_code,int8_t major,int8_t minor){
      char current_time_str[32] = {0};
    unused(current_time_str);

    rebrick_http_header_t *tmp = new (rebrick_http_header_t);
    constructor(tmp, rebrick_http_header_t);
    if (status_code)
    {
        size_t len=strlen(status_code);
        if (len > REBRICK_HTTP_MAX_STATUSCODE_LEN - 1)
            return REBRICK_ERR_BAD_ARGUMENT;
        memcpy(tmp->status_code_str, status_code,len);
    }
    tmp->status_code=status;
    tmp->is_request=FALSE;
    tmp->major_version = major;
    tmp->minor_version = minor;

    *header = tmp;
    return REBRICK_SUCCESS;
}
int32_t rebrick_http_header_new4(rebrick_http_header_t **header,int32_t status,const void *status_code,size_t status_code_len,int8_t major,int8_t minor){
    char current_time_str[32] = {0};
    unused(current_time_str);

    rebrick_http_header_t *tmp = new (rebrick_http_header_t);
    constructor(tmp, rebrick_http_header_t);
    if (status_code)
    {
        size_t len=status_code_len;
        if (len > REBRICK_HTTP_MAX_STATUSCODE_LEN - 1)
            return REBRICK_ERR_BAD_ARGUMENT;
        memcpy(tmp->status_code_str, status_code,len);
    }
    tmp->status_code=status;
    tmp->is_request=FALSE;
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
    HASH_ADD_STR(header->headers, key_lower, keyvalue);
    return REBRICK_SUCCESS;
}

int32_t rebrick_http_header_add_header2(rebrick_http_header_t *header, const char *key,size_t keylen, const char *value,size_t valuelen)
{
    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;
    if (!header || !key || !value)
        return REBRICK_ERR_BAD_ARGUMENT;
    rebrick_http_key_value_t *keyvalue;
    result = rebrick_http_key_value_new2(&keyvalue, key,keylen,value,valuelen);
    if (result)
        return result;

    HASH_ADD_STR(header->headers, key_lower, keyvalue);
    return REBRICK_SUCCESS;
}
int32_t rebrick_http_header_contains_key(rebrick_http_header_t *header, const char *key, int32_t *founded)
{
    if (!header || !key)
        return REBRICK_ERR_BAD_ARGUMENT;
        //to lower
    char keylower[REBRICK_HTTP_MAX_HEADER_KEY_LEN]={0};
    strncpy(keylower,key,REBRICK_HTTP_MAX_HEADER_KEY_LEN-1);
    string_to_lower(keylower);
    rebrick_http_key_value_t *keyvalue;
    HASH_FIND_STR(header->headers, keylower, keyvalue);
    *founded = FALSE;
    if (keyvalue)
        *founded = TRUE;
    return REBRICK_SUCCESS;
}
int32_t rebrick_http_header_get_header(rebrick_http_header_t *header,const char *key,const char **value){
     if (!header || !key)
        return REBRICK_ERR_BAD_ARGUMENT;
    rebrick_http_key_value_t *keyvalue;
     char keylower[REBRICK_HTTP_MAX_HEADER_KEY_LEN]={0};
    strncpy(keylower,key,REBRICK_HTTP_MAX_HEADER_KEY_LEN-1);
     string_to_lower(keylower);
    HASH_FIND_STR(header->headers, keylower, keyvalue);
    *value=NULL;
    if (keyvalue){
        *value=keyvalue->value;
    }

        return REBRICK_SUCCESS;
}
int32_t rebrick_http_header_remove_key(rebrick_http_header_t *header, const char *key)
{
    if (!header || !key)
        return REBRICK_ERR_BAD_ARGUMENT;

         char keylower[REBRICK_HTTP_MAX_HEADER_KEY_LEN]={0};
    strncpy(keylower,key,REBRICK_HTTP_MAX_HEADER_KEY_LEN-1);
    string_to_lower(keylower);
    rebrick_http_key_value_t *keyvalue;

    HASH_FIND_STR(header->headers, keylower, keyvalue);
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

int32_t rebrick_http_header_to_http_buffer(rebrick_http_header_t *header, rebrick_buffer_t **rbuffer)
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
    if(header->host){
        written_chars_count += snprintf(buffer + written_chars_count, REBRICK_HTTP_MAX_HEADER_LEN - written_chars_count, "%s:%s\r\n", "host",header->host);
        if (written_chars_count == REBRICK_HTTP_MAX_HEADER_LEN - 1)
        {
            rebrick_log_error("max http header len\n");
            return REBRICK_ERR_LEN_NOT_ENOUGH;
        }
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


static nghttp2_nv convert_to_http2_header(const char *name,size_t namelen,const char *value,size_t valuelen){
    nghttp2_nv nv;
    nv.flags=NGHTTP2_NV_FLAG_NONE;

    nv.name=malloc(namelen);
    nv.namelen=namelen;
    memcpy(nv.name,name,namelen);

    nv.value=malloc(valuelen);
    nv.valuelen=valuelen;
    memcpy(nv.value,value,valuelen);
    return nv;

}

int32_t rebrick_http_header_to_http2_buffer(rebrick_http_header_t *header, rebrick_buffer_t **rbuffer)
{
    char current_time_str[32] = {0};
    unused(current_time_str);
    if (!header)
        return REBRICK_ERR_BAD_ARGUMENT;

    nghttp2_nv hdrs[REBRICK_HTTP_MAX_HEADERS];
    unused(hdrs);
    int32_t index=0;
     if(header->scheme && header->scheme[0]){
        const char *scheme=header->scheme;
        size_t schemelen=strlen(scheme);
        hdrs[index++]=convert_to_http2_header(":scheme",7,scheme,schemelen);
    }

    if(header->host && header->host[0]){
         const char *host=header->host;
        size_t hostlen=strlen(host);
        hdrs[index++]=convert_to_http2_header(":authority",10,host,hostlen);
    }



    if(header->method){
        const char *path=header->method[0]?header->method:"GET";
        size_t pathlen=strlen(path);
        hdrs[index++]=convert_to_http2_header(":method",7,path,pathlen);
    }
     if (header->path){
        const char *path=header->path[0]?header->path:"/";
        size_t pathlen=strlen(path);
         hdrs[index++]=convert_to_http2_header(":path",5,path,pathlen);
    }





    rebrick_http_key_value_t *s, *tmp;
    HASH_ITER(hh, header->headers, s, tmp)
    {
        if(index>=REBRICK_HTTP_MAX_HEADERS)
        continue;
        hdrs[index++]=convert_to_http2_header(s->key,s->keylen,s->value,s->valuelen);


    }
    size_t len=sizeof(nghttp2_nv)*index;
    if(len>=REBRICK_HTTP_MAX_HEADER_LEN)
    return REBRICK_ERR_LEN_NOT_ENOUGH;

    rebrick_buffer_t *rtmp;
    int32_t result = rebrick_buffer_new(&rtmp, cast(hdrs,uint8_t*), len, REBRICK_HTTP_MAX_HEADER_LEN);
    if (result < 0)
        return result;

    *rbuffer = rtmp;

    return REBRICK_SUCCESS;
}