#ifndef __FERRUM_H__
#define __FERRUM_H__

#include "../rebrick/rebrick.h"

#define FERRUM_VERSION "1.3.0"

#define FERRUM_SUCCESS REBRICK_SUCCESS
#define ferrum_log_debug rebrick_log_debug
#define ferrum_log_info rebrick_log_info
#define ferrum_log_error rebrick_log_error
#define ferrum_log_fatal rebrick_log_fatal
#define ferrum_log_warn rebrick_log_warn

#define FERRUM_ERR_REDIS -5000
#define FERRUM_ERR_LMDB -6000
#define FERRUM_ERR_LMDB_ROW_NOT_FOUND -6001
#define FERRUM_ERR_POLICY 7000
#define FERRUM_ERR_DNS_BAD_PACKET 8000
#define FERRUM_ERR_DNS_NOT_QUERY 8001
#define FERRUM_ERR_DNS_BAD_ARGUMENT 8002
#define FERRUM_ERR_DNS 8003

#define FERRUM_ID_STR_LEN 32
#define FERRUM_ID_BIG_STR_LEN 96

#endif
