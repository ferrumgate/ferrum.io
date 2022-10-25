#ifndef __REBRICK_FILESTREAM_H__
#define __REBRICK_FILESTREAM_H__

#include "../common/rebrick_common.h"
#include "../common/rebrick_log.h"
#include "../common/rebrick_buffer.h"

struct rebrick_filestream;

typedef void (*rebrick_filestream_on_open_callback_t)(struct rebrick_filestream *stream, void *callback_data);
typedef void (*rebrick_filestream_on_read_callback_t)(struct rebrick_filestream *stream, void *callback_data, uint8_t *buf, size_t size);
typedef void (*rebrick_filestream_on_write_callback_t)(struct rebrick_filestream *stream, void *callback_data, uint8_t *buf, size_t size);
typedef void (*rebrick_filestream_on_close_callback_t)(struct rebrick_filestream *stream, void *callback_data);
typedef void (*rebrick_filestream_on_error_callback_t)(struct rebrick_filestream *stream, void *callback_data, int32_t error);

typedef struct rebrick_filestream_callbacks {
  base_object();
  protected_ void *callback_data;
  public_ rebrick_filestream_on_open_callback_t on_open;
  public_ rebrick_filestream_on_read_callback_t on_read;
  public_ rebrick_filestream_on_write_callback_t on_write;
  public_ rebrick_filestream_on_close_callback_t on_close;
  public_ rebrick_filestream_on_error_callback_t on_error;

} rebrick_filestream_callbacks_t;

public_ typedef struct rebrick_filestream {
  base_object();

  private_ uv_buf_t read_buf;
  private_ uv_buf_t write_buf;
  private_ uv_fs_t read_request;
  private_ uv_fs_t open_request;
  private_ uv_fs_t close_request;
  private_ uv_fs_t write_request;
  protected_ void *callback_data;
  public_ readonly_ char path[PATH_MAX];
  public_ rebrick_filestream_on_open_callback_t on_open;
  public_ rebrick_filestream_on_read_callback_t on_read;
  public_ rebrick_filestream_on_write_callback_t on_write;
  public_ rebrick_filestream_on_close_callback_t on_close;
  public_ rebrick_filestream_on_error_callback_t on_error;

} rebrick_filestream_t;

#define cast_to_filestream(x) cast(x, rebrick_filestream_t *)

int32_t rebrick_filestream_new(rebrick_filestream_t **stream, const char *path, int32_t flag, int32_t mode, const rebrick_filestream_callbacks_t *callbacks);
int32_t rebrick_filestream_read(rebrick_filestream_t *stream, uint8_t *buffer, size_t len, int64_t offset);
int32_t rebrick_filestream_read_all(rebrick_filestream_t *stream, rebrick_buffer_t **buffer, size_t readlen, int64_t offset);
int32_t rebrick_filestream_write(rebrick_filestream_t *stream, uint8_t *buffer, size_t len, int64_t offset);
int32_t rebrick_filestream_destroy(rebrick_filestream_t *stream);

#endif