#ifndef __REBRICK_FILESTREAM_H__
#define __REBRICK_FILESTREAM_H__

#include "../common/rebrick_common.h"

public_ typedef struct rebrick_filestream{
    base_object();
    private_ uv_buf_t read_buf;
    private_ uv_fs_t read_request;
    private_ uv_fs_t open_request;
    protected_ void *callback;
    public_ readonly_ char path[PATH_MAX];

}rebrick_filestream_t;


typedef void (*rebrick_filestream_on_open_callback_t)(rebrick_filestream_t *stream,void *callback_data);
typedef void (*rebrick_filestream_on_read_callback_t)(rebrick_filestream_t *stream,void *callback_data);
typedef void (*rebrick_filestream_on_write_callback_t)(rebrick_filestream_t *stream,void *callback_data);
typedef void (*rebrick_filestream_on_close_callback_t)(rebrick_filestream *stream,void *callback_data);
typedef void (*rebrick_filestream_on_error_callback_t)(rebrick_filestream_t *stream,void *callback_data,int32_t error);


typedef struct rebrick_filestream_callbacks{
    base_object();
    public_ rebrick_filestream_on_open_callback_t on_open;
    public_ rebrick_filestream_on_read_callback_t on_read;
    public_ rebrick_filestream_on_write_callback_t on_write;
    public_ rebrick_filestream_on_close_callback_t on_close;
    public_ rebrick_filestream_on_error_callback_t on_error;

}rebrick_filestream_callbacks_t;

int32_t rebrick_filestream_new(rebrick_filestream_t **stream,const char *path,const char *mode,size_t readsize);
int32_t rebrick_filestream_read(rebrick_filestream_t *stream,const uint8_t *buffer,size_t len);
int32_t rebrick_filestream_write(rebrick_filestream_t *stream,uint8_t *buffer, size_t len, rebrick_clean_func_t clean_func);
int32_t rebrick_filestream_destroy(rebrick_filestream_t *stream);

#endif