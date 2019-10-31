#ifndef __REBRICK_BUFFERS_H__
#define __REBRICK_BUFFERS_H__

#include "rebrick_common.h"
#include "rebrick_log.h"
#include "../lib/utlist.h"




public_ typedef struct rebrick_buffers_page{
   base_object();
   public_ readonly_ uint8_t *buf;
   public_ readonly_ size_t len;
   public_ readonly_ struct rebrick_buffers_page *next;
   public_ readonly_ struct rebrick_buffers_page *prev;
}rebrick_buffers_page_t;


public_ typedef struct rebrick_buffers{
   base_object();
   public_ readonly_ rebrick_buffers_page_t *head_page;
   public_ readonly_ size_t malloc_size;

}rebrick_buffers_t;


int32_t rebrick_buffers_new(rebrick_buffers_t **buffer,uint8_t *buf,size_t len,size_t mallocsize);


/**
 * @brief destroys a buffer
 *
 * @param buffer
 * @return int32_t return REBRICK_SUCCESS otherwise error
 */
int32_t rebrick_buffers_destroy(rebrick_buffers_t *buffer);

/**
 * @brief add a new buffer to head of buffers
 *
 * @param buffer
 * @param buf
 * @param len
 * @return int32_t
 */
int32_t rebrick_buffers_add(rebrick_buffers_t *buffer,uint8_t *buf,size_t len);




/**
 * @brief removes a part of buffer
 *
 * @param buffer
 * @param start
 * @param count
 * @return int32_t
 */
int32_t rebrick_buffers_remove(rebrick_buffers_t *buffer,size_t start,size_t count);


/**
 * @brief returns total sizeof buffer
 *
 * @param buffer
 * @return int32_t <0 means error otherwise total length of buffer in bytes
 */
int32_t rebrick_buffers_total_len(rebrick_buffers_t *buffer);



int32_t rebrick_buffers_to_array(const rebrick_buffers_t *buffer,uint8_t **array,size_t *arr_len);










#endif