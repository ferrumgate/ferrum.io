#include "rebrick_buffers.h"

int32_t rebrick_buffers_new(rebrick_buffers_t **buffer, uint8_t *buf, size_t len,size_t malloc_size)
{
    char current_time_str[32] = {0};
    unused(current_time_str);
    if (!buffer || !buf || !len)
        return REBRICK_ERR_BAD_ARGUMENT;

    if(!malloc_size)
    malloc_size=(size_t)1024;

    rebrick_buffers_t *buf_tmp = new (rebrick_buffers_t);
    constructor(buf_tmp, rebrick_buffers_t);

    buf_tmp->head_page = NULL;
    buf_tmp->malloc_size=malloc_size;
    int32_t default_malloc_size=malloc_size;
    int32_t copied_size;
    int32_t remain_size = len;
    int32_t total_size = 0;
    while (remain_size > 0)
    {
        rebrick_buffers_page_t *tmp = new (rebrick_buffers_page_t);
        constructor(tmp, rebrick_buffers_page_t);
        tmp->buf=malloc(default_malloc_size);
        if_is_null_then_die(tmp->buf,"malloc problem\n");
        memset(tmp->buf,0,default_malloc_size);

        copied_size = remain_size > default_malloc_size ? default_malloc_size : remain_size;
        memcpy(tmp->buf, buf + total_size, copied_size);
        total_size += copied_size;
        remain_size -= copied_size;
        tmp->len = copied_size;

        DL_APPEND(buf_tmp->head_page, tmp);
    }
    *buffer = buf_tmp;
    return REBRICK_SUCCESS;
}

int32_t rebrick_buffers_destroy(rebrick_buffers_t *buffer)
{
    if (buffer)
    {

        char current_time_str[32] = {0};
        unused(current_time_str);
        if (buffer->head_page)
        {
            rebrick_buffers_page_t *elt, *tmp;
            DL_FOREACH_SAFE(buffer->head_page, elt, tmp)
            {
                DL_DELETE(buffer->head_page, elt);
                if(elt->buf)
                free(elt->buf);
                free(elt);
            }
        }
        free(buffer);
    }
    return REBRICK_SUCCESS;
}

int32_t rebrick_buffers_add(rebrick_buffers_t *buffer, uint8_t *buf, size_t len)
{
    char current_time_str[32] = {0};
    unused(current_time_str);

    if (!buffer || !buf || !len)
        return REBRICK_ERR_BAD_ARGUMENT;

    rebrick_buffers_page_t *last_elm = buffer->head_page->prev;
    if (!last_elm)
        last_elm = buffer->head_page;

    size_t default_malloc_size=buffer->malloc_size;
    int32_t space_len;

    int32_t copied_size;
    int32_t remain_size = len;
    int32_t total_size = 0;
    while (remain_size > 0)
    {
        space_len = default_malloc_size - last_elm->len;
        copied_size = remain_size > space_len ? space_len : remain_size;
        if (copied_size == 0)
        {
            rebrick_buffers_page_t *tmp = new (rebrick_buffers_page_t);
            constructor(tmp, rebrick_buffers_page_t);
            tmp->buf=malloc(default_malloc_size);
            if_is_null_then_die(tmp->buf,"malloc problem\n");
            memset(tmp->buf,0,default_malloc_size);
            last_elm = tmp;
            DL_APPEND(buffer->head_page, tmp);
            space_len = default_malloc_size - last_elm->len;
            copied_size = remain_size > space_len ? space_len : remain_size;
        }
        memcpy(last_elm->buf + last_elm->len, buf + total_size, copied_size);
        total_size += copied_size;
        remain_size -= copied_size;
        last_elm->len += copied_size;
    }

    return REBRICK_SUCCESS;
}

int32_t rebrick_buffers_remove(rebrick_buffers_t *buffer, size_t start, size_t count)
{
    char current_time_str[32] = {0};
    unused(current_time_str);
    if (!buffer || !buffer->head_page || !buffer->head_page->buf || !count)
        return REBRICK_ERR_BAD_ARGUMENT;
    int32_t default_malloc_size=buffer->malloc_size;
    rebrick_buffers_page_t *head = buffer->head_page;
    rebrick_buffers_page_t *start_page = head;
    rebrick_buffers_page_t *del_point;
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
        s_removelen = s_count > default_malloc_size ? default_malloc_size : s_count;
        if (s_removelen == (int32_t)start_page->len)
        { //page tamamem silinecek demektir
            s_count -= start_page->len;
            del_point = start_page;
            start_page = start_page->next;
            DL_DELETE(head, del_point);
            if(del_point->buf)
            free(del_point->buf);
            free(del_point);
            buffer->head_page = head;
        }
        else
        {
            uint8_t tmp[default_malloc_size];// = {0};
            if (offset)
            {
                memcpy(tmp, start_page->buf, offset);
                memcpy(tmp + offset, start_page->buf + offset+s_removelen, start_page->len - offset - s_removelen);
            }
            else
            {
                memcpy(tmp, start_page->buf + offset + s_removelen, start_page->len - offset - s_removelen);
            }

            memcpy(start_page->buf, tmp, default_malloc_size);
            s_count -= start_page->len;
            start_page->len -= s_removelen;
        }
    }

    return REBRICK_SUCCESS;
}

int32_t rebrick_buffers_total_len(rebrick_buffers_t *buffer)
{
    char current_time_str[32] = {0};
    unused(current_time_str);
    if (!buffer)
        return REBRICK_ERR_BAD_ARGUMENT;
    if (!buffer->head_page)
        return 0;
    int32_t sum = 0;
    rebrick_buffers_page_t *tmp;
    DL_FOREACH(buffer->head_page, tmp)
    {
        sum += tmp->len;
    }

    return sum;
}


int32_t rebrick_buffers_to_array(rebrick_buffers_t *buffer,uint8_t **array,size_t *arr_len){
     char current_time_str[32] = {0};
    unused(current_time_str);
    *arr_len=0;
    *array=NULL;
    if(buffer){
        uint8_t *temp=NULL;
        int32_t sum = 0;
        rebrick_buffers_page_t *tmp;
        DL_FOREACH(buffer->head_page, tmp)
        {
            sum += tmp->len;
        }
        temp=malloc(sum);
        if_is_null_then_die(temp,"malloc problem\n");

        int32_t index=0;
        DL_FOREACH(buffer->head_page, tmp)
        {
            memcpy(temp+index,tmp->buf,tmp->len);
            index += tmp->len;
        }
        *array=temp;
        *arr_len=sum;

    }
    return REBRICK_SUCCESS;


}
