#include "rebrick_buffer.h"

int32_t rebrick_buffer_new(rebrick_buffer_t **buffer, uint8_t *buf, size_t len, size_t malloc_size)
{

    char current_time_str[32] = {0};
    unused(current_time_str);
    if (!buffer || !buf || !len)
        return REBRICK_ERR_BAD_ARGUMENT;
    if (!malloc_size)
        malloc_size = (size_t)1024;

    rebrick_buffer_t *buf_tmp = new (rebrick_buffer_t);
    constructor(buf_tmp, rebrick_buffer_t);
    buf_tmp->malloc_size = malloc_size;

    size_t m_len = 0;

    if (buf_tmp->malloc_len - buf_tmp->len < len)
    {
        m_len = ((len + malloc_size - 1) / malloc_size) * malloc_size;

        buf_tmp->buf = realloc(buf_tmp->buf, m_len);
        if_is_null_then_die(buf_tmp->buf, "malloc problem\n");
    }
    memcpy(buf_tmp->buf + buf_tmp->len, buf, len);
    buf_tmp->len += len;
    buf_tmp->malloc_len += m_len;

    *buffer = buf_tmp;
    return REBRICK_SUCCESS;
}

/**
 * @brief destroys a buffer
 *
 * @param buffer
 * @return int32_t return REBRICK_SUCCESS otherwise error
 */
int32_t rebrick_buffer_destroy(rebrick_buffer_t *buffer)
{
    char current_time_str[32] = {0};
    unused(current_time_str);
    if (buffer)
    {
        if (buffer->buf)
            free(buffer->buf);
        free(buffer);
    }
    return REBRICK_SUCCESS;
}

/**
 * @brief add a new buffer to head of buffers
 *
 * @param buffer
 * @param buf
 * @param len
 * @return int32_t
 */
int32_t rebrick_buffer_add(rebrick_buffer_t *buffer, uint8_t *buf, size_t len)
{
    char current_time_str[32] = {0};
    unused(current_time_str);
    if (!buffer || !buf || !len)
        return REBRICK_ERR_BAD_ARGUMENT;

    size_t m_len = 0;
    size_t malloc_size = buffer->malloc_size;

    if (buffer->malloc_len - buffer->len < len)
    {
        m_len = ((abs(buffer->malloc_len-buffer->len-len) + malloc_size - 1) / malloc_size) * malloc_size+buffer->malloc_len;

        buffer->buf = realloc(buffer->buf, m_len);
        if_is_null_then_die(buffer->buf, "malloc problem\n");
        m_len=m_len-buffer->malloc_len;
    }
    memcpy(buffer->buf + buffer->len, buf, len);
    buffer->len += len;
    buffer->malloc_len += m_len;

    return REBRICK_SUCCESS;
}

/**
 * @brief removes a part of buffer
 *
 * @param buffer
 * @param start
 * @param count
 * @return int32_t
 */
int32_t rebrick_buffer_remove(rebrick_buffer_t *buffer, size_t start, size_t count)
{
    char current_time_str[32] = {0};
    unused(current_time_str);
    if (!buffer || !count)
        return REBRICK_ERR_BAD_ARGUMENT;

    if (start >= buffer->len)
        return REBRICK_ERR_BAD_ARGUMENT;
    if (start + count >= buffer->len)
    {
        count = buffer->len - start;
    }
    if (!count)
        return REBRICK_ERR_BAD_ARGUMENT;
    size_t size = buffer->len - count;
    if(start+count<buffer->len)
    memmove(buffer->buf + start, buffer->buf + start + count, size);
    buffer->len -= count;

    size_t total_len_must_be = ((buffer->len + (buffer->malloc_size - 1)) / buffer->malloc_size) * buffer->malloc_size;
    if(total_len_must_be==0)
    total_len_must_be=buffer->malloc_size;

    if (total_len_must_be != buffer->malloc_len)
    {
        buffer->buf = realloc(buffer->buf, total_len_must_be);
        buffer->malloc_len = total_len_must_be;
    }

    return REBRICK_SUCCESS;
}