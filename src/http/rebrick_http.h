#ifndef __REBRICK_HTTP_H__
#define __REBRICK_HTTP_H__

#include "../socket/rebrick_tlssocket.h"
#include "../common/rebrick_buffer.h"
#include "../lib/picohttpparser.h"
#include "../lib/uthash.h"
#include "./nghttp2/nghttp2.h"


#define REBRICK_HTTP_VERSION1 1
#define REBRICK_HTTP_VERSION2 2


#define REBRICK_HTTP_BUFFER_MALLOC 8192

#define REBRICK_HTTP_MAX_HEADER_LEN 8192
#define REBRICK_HTTP_MAX_HEADER_KEY_LEN 128
#define REBRICK_HTTP_MAX_HOSTNAME_LEN 1024
#define REBRICK_HTTP_MAX_URI_LEN 8192
#define REBRICK_HTTP_MAX_PATH_LEN 8192
#define REBRICK_HTTP_MAX_METHOD_LEN 16
#define REBRICK_HTTP_MAX_SCHEME_LEN 16
#define REBRICK_HTTP_MAX_STATUSCODE_LEN 64
#define REBRICK_HTTP_MAX_HEADERS 96




public_ typedef struct rebrick_http_key_value{
    public_ readonly_ char *key;
    public_ size_t keylen;
    public_ readonly_ char *key_lower;
    public_ readonly_ char *value;
    public_ size_t valuelen;
    UT_hash_handle hh;
}rebrick_http_key_value_t;

int32_t rebrick_http_key_value_new(rebrick_http_key_value_t **keyvalue,const char *key,const char *value);
int32_t rebrick_http_key_value_new2(rebrick_http_key_value_t **keyvalue,const void *key,size_t keylen,const void *value,size_t valuelen);
int32_t rebrick_http_key_value_destroy(rebrick_http_key_value_t *keyvalue);

public_ typedef struct rebrick_http_header{
    base_object();
    public_ char path[REBRICK_HTTP_MAX_PATH_LEN];
    public_ char method[REBRICK_HTTP_MAX_METHOD_LEN];
    public_ char scheme[REBRICK_HTTP_MAX_SCHEME_LEN];
    public_ char host[REBRICK_HTTP_MAX_HOSTNAME_LEN];
    public_ int8_t major_version;
    public_ int8_t minor_version;
    public_ int16_t status_code;
    public_ char status_code_str[REBRICK_HTTP_MAX_STATUSCODE_LEN];
    public_ rebrick_http_key_value_t *headers;
    public_ int32_t is_request;
    //http2 supporting
    public_ int32_t stream_id;



}rebrick_http_header_t;


int32_t rebrick_http_header_new(rebrick_http_header_t **header,const char *scheme,const char*host,const char *method,const char *path,int8_t major,int8_t minor);
int32_t rebrick_http_header_new2(rebrick_http_header_t **header,const char *scheme,size_t scheme_len,const char*host,size_t host_len, const void *method,size_t method_len,const void *path,size_t path_len,int8_t major,int8_t minor);
int32_t rebrick_http_header_new3(rebrick_http_header_t **header,int32_t status,const char *status_code,int8_t major,int8_t minor);
int32_t rebrick_http_header_new4(rebrick_http_header_t **header,int32_t status,const void *status_code,size_t status_code_len,int8_t major,int8_t minor);
int32_t rebrick_http_header_add_header(rebrick_http_header_t *header,const char *key,const char*value);
int32_t rebrick_http_header_add_header2(rebrick_http_header_t *header,const char *key,size_t keylen,const char*value,size_t valuelen);
int32_t rebrick_http_header_contains_key(rebrick_http_header_t *header,const char *key,int32_t *founded);
int32_t rebrick_http_header_get_header(rebrick_http_header_t *header,const char *key,const char **value);
int32_t rebrick_http_header_remove_key(rebrick_http_header_t *header,const char *key);
int32_t rebrick_http_header_destroy(rebrick_http_header_t *header);
int32_t rebrick_http_header_to_http_buffer(rebrick_http_header_t *header,rebrick_buffer_t **buffer);
int32_t rebrick_http_header_to_http2_buffer(rebrick_http_header_t *header,rebrick_buffer_t **buffer);



#endif