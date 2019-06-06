#ifndef __REBRICK_ASYNC_SOCKET_H__
#define __REBRICK_ASYNC_SOCKET_H__
#include "rebrick_common.h"
#include "rebrick_log.h"
#include "./lib/utlist.h"





typedef int32_t (*rebrick_after_data_received_callback_t)(void *callback_data,const struct sockaddr *addr, const char *buffer,size_t len);
typedef int32_t (*rebrick_after_data_sended_callback_t)(void *callback_data,int status);





#endif