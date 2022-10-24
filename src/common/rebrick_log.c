#include "rebrick_log.h"

static log_level_t log_level = REBRICK_LOG_ERROR;
void rebrick_log_level(log_level_t level)
{
    log_level = level;
}
void rebrick_log_info(const char *file, int32_t line, const char *fmt, ...)
{
    if (log_level >= REBRICK_LOG_INFO)
    {
        char current_time_str[32] = {0};
        unused(current_time_str);
        fprintf(stderr, "[%s] [INFO] %s:%d - ", rebrick_util_time_r(current_time_str), file, line);
        va_list myargs;
        va_start(myargs, fmt);
        fprintf(stderr, fmt, myargs);
        va_end(myargs);
    }
}
void rebrick_log_debug(const char *file, int32_t line, const char *fmt, ...)
{
    if (log_level >= REBRICK_LOG_DEBUG)
    {
        char current_time_str[32] = {0};
        unused(current_time_str);
        fprintf(stderr, "[%s] [DEBUG] %s:%d - ", rebrick_util_time_r(current_time_str), file, line);
        va_list myargs;
        va_start(myargs, fmt);
        fprintf(stderr, fmt, myargs);
        va_end(myargs);
    }
}

void rebrick_log_fatal(const char *file, int32_t line, const char *fmt, ...)
{
    if (log_level >= REBRICK_LOG_FATAL)
    {
        char current_time_str[32] = {0};
        unused(current_time_str);
        fprintf(stderr, "[%s] [FATAL] %s:%d - ", rebrick_util_time_r(current_time_str), file, line);
        va_list myargs;
        va_start(myargs, fmt);
        fprintf(stderr, fmt, myargs);
        va_end(myargs);
    }
}

void rebrick_log_error(const char *file, int32_t line, const char *fmt, ...)
{
    if (log_level >= REBRICK_LOG_FATAL)
    {
        char current_time_str[32] = {0};
        unused(current_time_str);
        fprintf(stderr, "[%s] [ERROR] %s:%d - ", rebrick_util_time_r(current_time_str), file, line);
        va_list myargs;
        va_start(myargs, fmt);
        fprintf(stderr, fmt, myargs);
        va_end(myargs);
    }
}