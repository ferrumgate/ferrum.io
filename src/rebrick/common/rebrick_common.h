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
#define REBRICK_ERR_HTTP2 -20000
#define REBRICK_ERR_MALLOC -1        // 0xFFFFFFFF
#define REBRICK_ERR_CONFIG_CREATE -2 // 0xFFFFFFFE
#define REBRICK_ERR_BAD_ARGUMENT -3
#define REBRICK_ERR_SPRINTF -4
#define REBRICK_ERR_BAD_CONFIG_ARGUMENT -5
#define REBRICK_ERR_BAD_IP_PORT_ARGUMENT -6
#define REBRICK_ERR_ASSERT_NOT_NULL -7
#define REBRICK_ERR_MORE_BUFFER -8
#define REBRICK_ERR_CLIENT_CREATE -9
#define REBRICK_ERR_IO_CLOSED -10
#define REBRICK_ERR_IO_CLOSING -11
#define REBRICK_ERR_IO_END -12
#define REBRICK_ERR_RESOLV -13
#define REBRICK_ERR_IO_RECONNECT -14
#define REBRICK_ERR_IO_FULL_BUFFER -15
#define REBRICK_ERR_IO_ERR -19

#define REBRICK_ERR_TLS_INIT -20
#define REBRICK_ERR_TLS_NEW -21
#define REBRICK_ERR_TLS_ERR -22
#define REBRICK_ERR_TLS_INIT_NOT_FINISHED -23
#define REBRICK_ERR_TLS_READ -24
#define REBRICK_ERR_TLS_WRITE -25
#define REBRICK_ERR_TLS_CLOSED -26

#define REBRICK_ERR_LEN_NOT_ENOUGH -30
#define REBRICK_ERR_UNSUPPORT_IPFAMILY -31

#define REBRICK_ERR_NOT_FOUND -50

#define REBRICK_ERR_HTTP_HEADER_PARSE -100

#define REBRICK_ERR_HTTP2_STREAM_NOT_FOUND -500
#define REBRICK_ERR_HTTP2_GOAWAY -501
#define REBRICK_ERR_HTTP2_PUSH_NOTSUPPORT -502

#define HAS_UV_ERR(result) ((result) < REBRICK_ERR_UV)
#define UV_ERR(result) (result) - (REBRICK_ERR_UV)

/*
 * @brief every struct has a type name, sometimes we are using for detect memory leak
 */
#define REBRICK_STRUCT_NAME_LEN 48

/*
 * @brief ip max string len
 */
#define REBRICK_IP_STR_LEN 64
#define REBRICK_PASS_STR_LEN 128

#define REBRICK_DOMAIN_LEN 2048
#define REBRICK_HOSTNAME_LEN 64
#define REBRICK_MAX_ENV_LEN 64
#define REBRICK_PORT_STR_LEN 8
#define REBRICK_HOST_STR_LEN 64
#define REBRICK_NAME_STR_LEN 64
#define REBRICK_IP_PORT_STR_LEN 96

#define REBRICK_TLS_KEY_LEN 128
#define REBRICK_CA_VERIFY_PATH_MAX_LEN 1024
#define REBRICK_TLS_ALPN_MAX_LEN 128

#define rebrick_kill_current_process(n) exit(n)
/* @brief allocation methods */
#define rebrick_malloc(x) malloc(x)
#define rebrick_free(x) free(x)
#define rebrick_realloc(x, y) realloc(x, y)
#define rebrick_calloc(x, y) calloc(x, y)

#define new1(x) rebrick_malloc(sizeof(x))

#define constructor(x, y)                  \
  if (!x) {                                \
    rebrick_log_fatal("malloc problem\n"); \
    exit(1);                               \
  }                                        \
  fill_zero(x, sizeof(y));                 \
  strncpy(x->type_name, #y, REBRICK_STRUCT_NAME_LEN - 1);

#define new2(y, x)          \
  y x;                      \
  fill_zero(&x, sizeof(y)); \
  strncpy(x.type_name, #y, REBRICK_STRUCT_NAME_LEN - 1);

#define new3(y, x) \
  y x;             \
  fill_zero(&x, sizeof(y));

#define new4(y, x)                  \
  y *x = rebrick_malloc(sizeof(y)); \
  fill_zero(x, sizeof(y));          \
  if_is_null_then_die(x, "malloc problem\n")

#define rebrick_malloc2(x, y) \
  x = rebrick_malloc(y);      \
  fill_zero(x, y);            \
  if_is_null_then_die(x, "malloc problem\n")

#define new_array(x, len) malloc(sizeof(x) * (len))
#define fill_zero(x, size) memset((x), 0, (size))
#define cast(x, y) ((y)(x))
#define const_cast(x, y) ((y)(x))

#define unused(x) (void)(x)
#define if_is_null_then_die(x, y) \
  if (!x) {                       \
    rebrick_log_fatal(y);         \
    exit(1);                      \
  }

/**
 * @brief base class for every structs
 *
 */
#define base_object(x) public_ readonly_ char type_name[REBRICK_STRUCT_NAME_LEN]

#define typeof(x, y) !strcmp((x)->type_name, #y)

#define ssizeof(x) cast(sizeof(x), int32_t)

#define cast_to_uint8ptr(x) cast(x, uint8_t *)
#define cast_to_const_uint8ptr(x) cast(x, const uint8_t *)
#define cast_to_charptr(x) cast(x, char *)
#define cast_to_const_charptr(x) cast(x, const char *)
#define cast_to_sockaddr(x) cast(x, struct sockaddr *)

#define public_
#define private_
#define readonly_
#define protected_
#define internal_

/**
 * @brief socket address union
 *
 */
typedef union rebrick_sockaddr {
  struct sockaddr base;
  struct sockaddr_in v4;
  struct sockaddr_in6 v6;
} rebrick_sockaddr_t;

//////////////// rebrick clean func //////////////////////

typedef void (*rebrick_clean_func_ptr_t)(void *ptr);

typedef struct rebrick_clean_func {
  base_object();
  // free function
  public_ rebrick_clean_func_ptr_t func;
  // ptr for free
  public_ void *ptr;
  // any data for you
  union {
    int32_t source;
    void *ptr;
  } anydata;

} rebrick_clean_func_t;

#endif
