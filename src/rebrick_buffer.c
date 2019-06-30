#include "rebrick_buffer.h"

int32_t rebrick_buffer_new(rebrick_buffer_t **buffer, size_t realloc_len)
{
    char current_time_str[32] = {0};
    unused(current_time_str);
    rebrick_buffer_t *tmp = new (rebrick_buffer_t);
    constructor(tmp, rebrick_buffer_t);
    tmp->realloc_len = realloc_len;

    *buffer = tmp;

    return REBRICK_SUCCESS;
}

int32_t rebrick_buffer_new2(rebrick_buffer_t **buffer)
{
    return rebrick_buffer_new(buffer, 128);
}
int32_t rebrick_buffer_destroy(rebrick_buffer_t *buffer)
{
    if (buffer)
    {
        if (buffer->buf)
        {
            free(buffer->buf);
        }
        free(buffer);
    }
    return REBRICK_SUCCESS;
}

int32_t rebrick_buffer_add(rebrick_buffer_t *buffer, uint8_t *buf, size_t len)
{
    char current_time_str[32] = {0};
    unused(current_time_str);

    if (!buffer || !buf || !len)
        return REBRICK_ERR_BAD_ARGUMENT;

    if (buffer->real_len < (buffer->len + len))
    {
        size_t newlen = buffer->real_len + buffer->realloc_len;
        while (newlen < buffer->len + len)
            newlen += buffer->realloc_len;
        buffer->buf = realloc(buffer->buf, newlen);
        if_is_null_then_die(buffer->buf, "realloc problem\n");

        buffer->real_len = newlen;
    }
    memcpy(buffer->buf + buffer->len, buf, len);
    buffer->len += len;
    return REBRICK_SUCCESS;
}

int32_t rebrick_buffer_remove(rebrick_buffer_t *buffer, size_t start, size_t count)
{
    char current_time_str[32] = {0};
    unused(current_time_str);
    if (!buffer || !buffer->buf || !count)
        return REBRICK_ERR_BAD_ARGUMENT;

    if (start + count > buffer->real_len)
    {
        return REBRICK_ERR_BAD_ARGUMENT;
    }
    uint8_t *newbuf = malloc(buffer->real_len);
    if_is_null_then_die(newbuf, "malloc problem\n");
    if (start)
    {
        memcpy(newbuf, buffer->buf, start);
        size_t len_tmp = start;
        size_t copylen = buffer->len - start - count;
        memcpy(newbuf + start, buffer->buf + start+count, copylen);
        buffer->len =len_tmp+ copylen;

    }
    else
    {
        memcpy(newbuf, buffer->buf + count, buffer->real_len - count);
        buffer->len -= count;
    }
    buffer->buf=newbuf;

    return REBRICK_SUCCESS;
}
