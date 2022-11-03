#ifndef __REBRICK_LOG_H__
#define __REBRICK_LOG_H__
#include "rebrick_common.h"
#include "rebrick_util.h"

typedef enum {
  REBRICK_LOG_OFF = 0,
  REBRICK_LOG_FATAL = 1,
  REBRICK_LOG_ERROR = 2,
  REBRICK_LOG_WARN = 3,
  REBRICK_LOG_INFO = 4,
  REBRICK_LOG_DEBUG = 5,
  REBRICK_LOG_ALL = 6
} log_level_t;

void rebrick_log_level(log_level_t level);

void rebrick_log_info2(const char *file, int32_t line, const char *fmt, ...);
void rebrick_log_debug2(const char *file, int32_t line, const char *fmt, ...);
void rebrick_log_fatal2(const char *file, int32_t line, const char *fmt, ...);
void rebrick_log_error2(const char *file, int32_t line, const char *fmt, ...);
void rebrick_log_warn2(const char *file, int32_t line, const char *fmt, ...);

#define rebrick_log_info(fmt, ...) rebrick_log_info2(__FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define rebrick_log_debug(fmt, ...) rebrick_log_debug2(__FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define rebrick_log_fatal(fmt, ...) rebrick_log_fatal2(__FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define rebrick_log_error(fmt, ...) rebrick_log_error2(__FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define rebrick_log_warn(fmt, ...) rebrick_log_warn2(__FILE__, __LINE__, fmt, ##__VA_ARGS__)

#endif
