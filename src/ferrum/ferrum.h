#ifndef __FERRUM_H__
#define __FERRUM_H__

#include "../rebrick/rebrick.h"

#define FERRUM_VERSION "1.4.0"

#define FERRUM_SUCCESS REBRICK_SUCCESS
#define ferrum_log_debug rebrick_log_debug
#define ferrum_log_info rebrick_log_info
#define ferrum_log_error rebrick_log_error
#define ferrum_log_fatal rebrick_log_fatal
#define ferrum_log_warn rebrick_log_warn

#define FERRUM_ERR_REDIS -5000
#define FERRUM_ERR_LMDB -6000
#define FERRUM_ERR_LMDB_ROW_NOT_FOUND -6001

#define FERRUM_ERR_BAD_ARGUMENT 6500
#define FERRUM_ERR_POLICY 7000
#define FERRUM_ERR_DNS_BAD_PACKET 8000
#define FERRUM_ERR_DNS_NOT_QUERY 8001
#define FERRUM_ERR_DNS_BAD_ARGUMENT 8002
#define FERRUM_ERR_DNS 8003
#define FERRUM_ERR_DNS_DB 8004

#define FERRUM_ERR_TRACK_DB 9000
#define FERRUM_ERR_TRACK_DB_PARSE 9001

#define FERRUM_ERR_AUTHZ_DB 10000
#define FERRUM_ERR_AUTHZ_DB_PARSE 10001

#define FERRUM_ERR_TRACK_ID_NOT_FOUND 11000

#define FERRUM_ID_STR_LEN 32
#define FERRUM_ID_BIG_STR_LEN 96
#define FERRUM_USER_MAX_GROUP_COUNT 16

#endif
