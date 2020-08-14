#ifndef __REBRICK_LOG_H__
#define __REBRICK_LOG_H__
#include "rebrick_common.h"
#include "rebrick_util.h"

#define rebrick_log_info(fmt, ...)                                                                      \
    fprintf(stderr, "[%s] [INFO] %s:%d - ", rebrick_util_time_r(current_time_str), __FILE__, __LINE__); \
    fprintf(stderr, fmt, ##__VA_ARGS__)

#define rebrick_log_debug(fmt, ...)                                                                      \
    fprintf(stderr, "[%s] [DEBUG] %s:%d - ", rebrick_util_time_r(current_time_str), __FILE__, __LINE__); \
    fprintf(stderr, fmt, ##__VA_ARGS__)

#define rebrick_log_fatal(fmt, ...)                                                                      \
    fprintf(stderr, "[%s] [FATAL] %s:%d - ", rebrick_util_time_r(current_time_str), __FILE__, __LINE__); \
    fprintf(stderr, fmt, ##__VA_ARGS__)

#define rebrick_log_error(fmt, ...)                                                                      \
    fprintf(stderr, "[%s] [ERROR] %s:%d - ", rebrick_util_time_r(current_time_str), __FILE__, __LINE__); \
    fprintf(stderr, fmt, ##__VA_ARGS__)

#endif
