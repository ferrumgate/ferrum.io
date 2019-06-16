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


/*
* @brief every struct has a typen name, sometimes we are using for detect memory leak
*/
#define REBRICK_STRUCT_NAME_LEN 32

/*
 * @brief ip max string len
 */
#define REBRICK_IP_STR_LEN 64

#define REBRICK_PORT_STR_LEN 8


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
#define base_class(x)  public_ readonly_ char type_name[REBRICK_STRUCT_NAME_LEN]



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
