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
void rebrick_log_info(const char *file, int32_t line, const char *fmt, ...);
void rebrick_log_debug(const char *file, int32_t line, const char *fmt, ...);
void rebrick_log_fatal(const char *file, int32_t line, const char *fmt, ...);
void rebrick_log_error(const char *file, int32_t line, const char *fmt, ...);

#endif
