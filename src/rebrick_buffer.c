#include "rebrick_buffer.h"

int32_t rebrick_buffer_new(rebrick_buffer_t **buffer, uint8_t *buf, size_t len)
{
    char current_time_str[32] = {0};
    unused(current_time_str);
    if (!buffer || !buf || !len)
        return REBRICK_ERR_BAD_ARGUMENT;

    rebrick_buffer_t *buf_tmp = new (rebrick_buffer_t);
    constructor(buf_tmp, rebrick_buffer_t);

    buf_tmp->head_page = NULL;

    int32_t copied_size;
    int32_t remain_size = len;
    int32_t total_size = 0;
    while (remain_size > 0)
    {
        rebrick_buffer_page_t *tmp = new (rebrick_buffer_page_t);
        constructor(tmp, rebrick_buffer_page_t);
        copied_size = remain_size > REBRICK_BUFFER_DEFAULT_MALLOC_SIZE ? REBRICK_BUFFER_DEFAULT_MALLOC_SIZE : remain_size;
        memcpy(tmp->buf, buf + total_size, copied_size);
        total_size += copied_size;
        remain_size -= copied_size;
        tmp->len = copied_size;

        DL_APPEND(buf_tmp->head_page, tmp);
    }
    *buffer = buf_tmp;
    return REBRICK_SUCCESS;
}

int32_t rebrick_buffer_destroy(rebrick_buffer_t *buffer)
{
    if (buffer)
    {

        char current_time_str[32] = {0};
        unused(current_time_str);
        if (buffer->head_page)
        {
            rebrick_buffer_page_t *elt, *tmp;
            DL_FOREACH_SAFE(buffer->head_page, elt, tmp)
            {
                DL_DELETE(buffer->head_page, elt);
                free(elt);
            }
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

    rebrick_buffer_page_t *last_elm = buffer->head_page->prev;
    if (!last_elm)
        last_elm = buffer->head_page;

    int32_t space_len;

    int32_t copied_size;
    int32_t remain_size = len;
    int32_t total_size = 0;
    while (remain_size > 0)
    {
        space_len = REBRICK_BUFFER_DEFAULT_MALLOC_SIZE - last_elm->len;
        copied_size = remain_size > space_len ? space_len : remain_size;
        if (copied_size == 0)
        {
            rebrick_buffer_page_t *tmp = new (rebrick_buffer_page_t);
            constructor(tmp, rebrick_buffer_page_t);
            last_elm = tmp;
            DL_APPEND(buffer->head_page, tmp);
            space_len = REBRICK_BUFFER_DEFAULT_MALLOC_SIZE - last_elm->len;
            copied_size = remain_size > space_len ? space_len : remain_size;
        }
        memcpy(last_elm->buf + last_elm->len, buf + total_size, copied_size);
        total_size += copied_size;
        remain_size -= copied_size;
        last_elm->len += copied_size;
    }

    return REBRICK_SUCCESS;
}

int32_t rebrick_buffer_remove(rebrick_buffer_t *buffer, size_t start, size_t count)
{
    char current_time_str[32] = {0};
    unused(current_time_str);
    if (!buffer || !buffer->head_page || !buffer->head_page->buf || !count)
        return REBRICK_ERR_BAD_ARGUMENT;
    rebrick_buffer_page_t *head = buffer->head_page;
    rebrick_buffer_page_t *start_page = head;
    rebrick_buffer_page_t *del_point;
    //int32_t s_len=0;
    int32_t s_count = count;
    int32_t s_removelen = 0;
    int32_t offset = 0;
    //find start page
    while (offset + start_page->len <= start)
    {
        offset += start_page->len;
        start_page = start_page->next;
    }
    //bulunan page te başlama noktası
    offset = start - offset;
    while (s_count > 0 && start_page)
    {
        s_removelen = s_count > REBRICK_BUFFER_DEFAULT_MALLOC_SIZE ? REBRICK_BUFFER_DEFAULT_MALLOC_SIZE : s_count;
        if (s_removelen == (int32_t)start_page->len)
        { //page tamamem silinecek demektir
            s_count -= start_page->len;
            del_point = start_page;
            start_page = start_page->next;
            DL_DELETE(head, del_point);
            free(del_point);
            buffer->head_page = head;
        }
        else
        {
            uint8_t tmp[REBRICK_BUFFER_DEFAULT_MALLOC_SIZE] = {0};
            if (offset)
            {
                memcpy(tmp, start_page->buf, offset);
                memcpy(tmp + offset, start_page->buf + offset+s_removelen, start_page->len - offset - s_removelen);
            }
            else
            {
                memcpy(tmp, start_page->buf + offset + s_removelen, start_page->len - offset - s_removelen);
            }

            memcpy(start_page->buf, tmp, REBRICK_BUFFER_DEFAULT_MALLOC_SIZE);
            s_count -= start_page->len;
            start_page->len -= s_removelen;
        }
    }

    return REBRICK_SUCCESS;
}

int32_t rebrick_buffer_total_len(rebrick_buffer_t *buffer)
{
    char current_time_str[32] = {0};
    unused(current_time_str);
    if (!buffer)
        return REBRICK_ERR_BAD_ARGUMENT;
    if (!buffer->head_page)
        return 0;
    int32_t sum = 0;
    rebrick_buffer_page_t *tmp;
    DL_FOREACH(buffer->head_page, tmp)
    {
        sum += tmp->len;
    }

    return sum;
}
