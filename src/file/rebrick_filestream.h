#ifndef __REBRICK_FILESTREAM_H__
#define __REBRICK_FILESTREAM_H__

#include "../common/rebrick_common.h"

public_ typedef struct rebrick_filestream{
    base_object();
    public_ readonly_ char path[PATH_MAX];
    void *callback;
}rebrick_filestream_t;


typedef void (*rebrick_filestream_on_open_callback_t)(rebrick_filestream_t *stream,void *callback_data);
typedef void (*rebrick_filestream_on_read_callback_t)(rebrick_filestream_t *stream,void *callback_data);
typedef void (*rebrick_filestream_on_write_callback_t)(rebrick_filestream_t *stream,void *callback_data);
typedef void (*rebrick_filestream_on_close_callback_t)(rebrick_filestream *stream,void *callback_data);
typedef void (*rebrick_filestream_on_error_callback_t)(rebrick_filestream_t *stream,void *callback_data,int32_t error);

int32_t rebrick_filestream_new(rebrick_filestream_t **stream,const char *path,const char *mode);
int32_t rebrick_filestream_destroy(rebrick_filestream_t *stream);

#endif