#ifndef __REBRICK_COMMON_H__
#define __REBRICK_COMMON_H__

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdarg.h>
#include <inttypes.h>
#include "uv.h"
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/engine.h>


#define TRUE 1
#define FALSE 0
/**
 * @brief errors and success, errors < 0
 */
#define REBRICK_SUCCESS 0
#define REBRICK_ERR_UV -10000
#define REBRICK_ERR_MALLOC -1        //0xFFFFFFFF
#define REBRICK_ERR_CONFIG_CREATE -2 //0xFFFFFFFE
#define REBRICK_ERR_BAD_ARGUMENT -3
#define REBRICK_ERR_SPRINTF -4
#define REBRICK_ERR_BAD_CONFIG_ARGUMENT -5
#define REBRICK_ERR_BAD_IP_PORT_ARGUMENT -6
#define REBRICK_ERR_ASSERT_NOT_NULL -7
#define REBRICK_ERR_MORE_BUFFER -8
#define REBRICK_ERR_CLIENT_CREATE -9
#define REBRICK_ERR_IO_CLOSED -10
#define REBRICK_ERR_IO_CLOSING -11
#define REBRICK_ERR_IO_ERR -12
#define REBRICK_ERR_LEN_NOT_ENOUGH -13




#define REBRICK_ERR_TLS_INIT -20
#define REBRICK_ERR_TLS_NEW -21
#define REBRICK_ERR_TLS_ERR -22
#define REBRICK_ERR_TLS_INIT_NOT_FINISHED -23
#define REBRICK_ERR_TLS_READ -24
#define REBRICK_ERR_TLS_WRITE -25
#define REBRICK_ERR_TLS_CLOSED -26



#define REBRICK_ERR_NOT_FOUND -50

#define REBRICK_ERR_HTTP_HEADER_PARSE -100


#define HAS_UV_ERR(result)  ((result)<REBRICK_ERR_UV)
#define UV_ERR(result)  (result)-(REBRICK_ERR_UV)

/*
* @brief every struct has a type name, sometimes we are using for detect memory leak
*/
#define REBRICK_STRUCT_NAME_LEN 32

/*
 * @brief ip max string len
 */
#define REBRICK_IP_STR_LEN 64

#define REBRICK_PORT_STR_LEN 8

#define REBRICK_TLS_KEY_LEN 128
#define REBRICK_CA_VERIFY_PATH_MAX_LEN 1024


/* @brief allocation methods */
#define new(x) malloc(sizeof(x))
#define constructor(x,y) \
                            if(!x) { \
                          rebrick_log_fatal("malloc problem\n");\
                          exit(1);\
                         } \
                         fill_zero(x,sizeof(y));\
                         strcpy(x->type_name,#y);

#define new_array(x, len) malloc(sizeof(x) * (len))
#define fill_zero(x, size) memset((x), 0, (size))
#define cast(x, y) ((y)x)
#define unused(x) (void)(x)
#define if_is_null_then_die(x,y) if(!x){ \
                              rebrick_log_fatal(y);\
                              exit(1);\
                              }


/**
 * @brief base class for every structs
 *
 */
#define base_object(x)  public_ readonly_ char type_name[REBRICK_STRUCT_NAME_LEN]

#define typeof(x,y) !strcmp((x)->type_name,#y)

#define ssizeof(x) cast(sizeof(x),int32_t)

#define cast_to_uint8ptr(x) cast(x,uint8_t*)
#define cast_to_const_uint8ptr(x) cast(x, const uint8_t*)
#define cast_to_charptr(x) cast(x,char *)
#define cast_to_const_charptr(x) cast(x,cont char*)





#define public_
#define private_
#define readonly_
#define protected_


/**
 * @brief socket address union
 *
 */
typedef union rebrick_sockaddr {
    struct sockaddr base;
    struct sockaddr_in v4;
    struct sockaddr_in6 v6;
}rebrick_sockaddr_t;

#endif