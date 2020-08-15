#include "rebrick_filestream.h"

static void on_file_open(uv_fs_t *req)
{
    // The request passed to the callback is the same as the one the call setup
    // function was passed.
    //assert(req == &open_req);
    char current_time_str[32] = {0};
    unused(current_time_str);
    rebrick_filestream_t *file = cast_to_filestream(req->data);
    uv_fs_req_cleanup(req);

    if (req->result >= 0)
    {

        if (file && file->on_open)
        {
            file->on_open(file, file->callback_data);
        }
    }
    else
    {
        rebrick_log_error(__FILE__, __LINE__, "error opening file: %s with error:%s\n", req->path, uv_strerror((int)req->result));
        if (file && file->on_error)
        {
            file->on_error(file, file->callback_data, req->result + REBRICK_ERR_UV);
        }
    }
}

int32_t rebrick_filestream_new(rebrick_filestream_t **stream, const char *path, int32_t flags, int32_t mode, const rebrick_filestream_callbacks_t *callbacks)
{
    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;

    rebrick_filestream_t *file = create(rebrick_filestream_t);
    constructor(file, rebrick_filestream_t);
    strncpy(file->path, path, PATH_MAX - 1);

    file->on_open = callbacks ? callbacks->on_open : NULL;
    file->on_error = callbacks ? callbacks->on_error : NULL;
    file->on_read = callbacks ? callbacks->on_read : NULL;
    file->on_write = callbacks ? callbacks->on_write : NULL;
    file->on_close = callbacks ? callbacks->on_close : NULL;

    //burası önemli,callback data
    file->callback_data = callbacks ? callbacks->callback_data : NULL;
    file->open_request.data = file;
    file->read_request.data = file;
    file->close_request.data = file;
    file->write_request.data = file;
    result = uv_fs_open(uv_default_loop(), &file->open_request, path, flags, mode, (callbacks && callbacks->on_open) ? on_file_open : NULL);
    if (result < 0)
    {
        uv_fs_req_cleanup(&file->open_request);
        free(file);
        rebrick_log_error(__FILE__, __LINE__, "file %s could not open:%s\n", path, uv_strerror(result));
        return REBRICK_ERR_UV + result;
    }
    if (!callbacks || !callbacks->on_open) //syncroinzed
        uv_fs_req_cleanup(&file->open_request);

    *stream = file;
    return REBRICK_SUCCESS;
}

void on_file_read(uv_fs_t *req)
{
    char current_time_str[32] = {0};
    unused(current_time_str);
    rebrick_filestream_t *file = cast_to_filestream(req->data);

    uv_fs_req_cleanup(req);

    if (req->result < 0)
    {
        rebrick_log_error(__FILE__, __LINE__, "file read error %s with error %s\n", req->path, uv_strerror(req->result));
        if (file && file->on_error)
            file->on_error(file, file->callback_data, REBRICK_ERR_UV + req->result);
    }
    else if (req->result == 0)
    {
        rebrick_log_info(__FILE__, __LINE__, "file close %s \n", req->path);
        if (file && file->on_error)
        {
            file->on_error(file, file->callback_data, REBRICK_ERR_IO_END);
        }
    }
    else if (req->result > 0)
    {
        if (file && file->on_read)
            file->on_read(file, file->callback_data, cast_to_uint8ptr(file->read_buf.base), req->result);
    }
}

int32_t rebrick_filestream_read(rebrick_filestream_t *stream, uint8_t *buffer, size_t len, int64_t offset)
{
    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;
    if (!stream || !buffer || !len)
        return REBRICK_ERR_BAD_ARGUMENT;
    stream->read_buf = uv_buf_init(cast(buffer, char *), len);
    result = uv_fs_read(uv_default_loop(), &stream->read_request, stream->open_request.result, &stream->read_buf, 1, offset, stream->on_read ? on_file_read : NULL);
    if (result < 0)
    {

        rebrick_log_error(__FILE__, __LINE__, "file read failed %s with error %s\n", stream->path, uv_strerror(result));
        return REBRICK_ERR_UV + result;
    }
    if (!stream->on_read)
    {
        uv_fs_req_cleanup(&stream->read_request);
        //sync function
        return result;
    }
    return REBRICK_SUCCESS;
}

void on_file_write(uv_fs_t *req)
{
    char current_time_str[32] = {0};
    unused(current_time_str);
    rebrick_filestream_t *file = cast_to_filestream(req->data);

    uv_fs_req_cleanup(req);

    if (req->result < 0)
    {
        rebrick_log_error(__FILE__, __LINE__, "file write error %s with error %s\n", req->path, uv_strerror(req->result));
        if (file && file->on_error)
            file->on_error(file, file->callback_data, REBRICK_ERR_UV + req->result);
    }
    else if (req->result == 0)
    {
        rebrick_log_info(__FILE__, __LINE__, "file close %s \n", req->path);
        if (file && file->on_close)
            file->on_close(file, file->callback_data);
    }
    else if (req->result > 0)
    {
        if (file && file->on_write)
            file->on_write(file, file->callback_data, cast_to_uint8ptr(file->write_buf.base), req->result);
    }
}

int32_t rebrick_filestream_write(rebrick_filestream_t *stream, uint8_t *buffer, size_t len, int64_t offset)
{
    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;
    if (!stream || !buffer || !len)
        return REBRICK_ERR_BAD_ARGUMENT;
    stream->write_buf = uv_buf_init(cast(buffer, char *), len);
    result = uv_fs_write(uv_default_loop(), &stream->write_request, stream->open_request.result, &stream->write_buf, 1, offset, stream->on_write ? on_file_write : NULL);
    if (result < 0)
    {

        rebrick_log_error(__FILE__, __LINE__, "file read failed %s with error %s\n", stream->path, uv_strerror(result));
        return REBRICK_ERR_UV + result;
    }

    if (!stream->on_write)
    {
        uv_fs_req_cleanup(&stream->write_request);
        //sync function
        return result;
    }
    return REBRICK_SUCCESS;
}

static void on_file_close(uv_fs_t *req)
{
    rebrick_filestream_t *stream = cast_to_filestream(req->data);
    if (stream)
    {
        if (stream->on_close)
            stream->on_close(stream, stream->callback_data);

        uv_fs_req_cleanup(req);
        free(stream);
    }
}

int32_t rebrick_filestream_destroy(rebrick_filestream_t *stream)
{
    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;
    if (stream)
    {
        if (stream->on_close)
        {

            result = uv_fs_close(uv_default_loop(), &stream->close_request, stream->open_request.result, on_file_close);
            if (result < 0)
            {
                rebrick_log_error(__FILE__, __LINE__, "file destroy failed %s with error %s\n", stream->path, uv_strerror(result));
                return REBRICK_ERR_UV + result;
            }
        }
        else
        {

            result = uv_fs_close(uv_default_loop(), &stream->close_request, stream->open_request.result, NULL);
            if (result < 0)
            {
                rebrick_log_error(__FILE__, __LINE__, "file destroy failed %s with error %s\n", stream->path, uv_strerror(result));
                return REBRICK_ERR_UV + result;
            }

            uv_fs_req_cleanup(&stream->close_request);
            free(stream);
        }
    }
    return REBRICK_SUCCESS;
}

int32_t rebrick_filestream_read_all(rebrick_filestream_t *stream, rebrick_buffer_t **buffer, size_t readlen, int64_t offset)
{
    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;
    if (!stream || !buffer)
        return REBRICK_ERR_BAD_ARGUMENT;

    rebrick_buffer_t *bf = NULL;
    int64_t offset_calculated = offset;
    size_t len = readlen ? readlen : 4096;
    char tmp[len];
    stream->read_buf = uv_buf_init(tmp, len);
    while (1)
    {
        result = uv_fs_read(uv_default_loop(), &stream->read_request, stream->open_request.result, &stream->read_buf, 1, offset_calculated, NULL);
        offset_calculated = -1;
        if (result < 0)
        {
            if (!bf)
                rebrick_buffer_destroy(bf);
            return result;
        }
        if (result == 0)
            break;
        if (bf)
            rebrick_buffer_add(bf, cast(tmp, uint8_t *), cast(result, size_t));
        else
            rebrick_buffer_new(&bf, cast(tmp, uint8_t *), cast(result, size_t), readlen * 2);
    }

    *buffer = bf;
    if (bf)
        return bf->len;
    return REBRICK_SUCCESS;
}
