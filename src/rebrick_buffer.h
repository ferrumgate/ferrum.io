#ifndef __REBRICK_BUFFER_H__
#define __REBRICK_BUFFER_H__

#include "rebrick_common.h"
#include "rebrick_log.h"
#include "./lib/utlist.h"

#define REBRICK_BUFFER_DEFAULT_MALLOC_SIZE 1024


public_ typedef struct rebrick_buffer_page{
   base_object();
   public_ readonly_ uint8_t buf[REBRICK_BUFFER_DEFAULT_MALLOC_SIZE];
   public_ readonly_ size_t len;
   public_ readonly_ struct rebrick_buffer_page *next;
   public_ readonly_ struct rebrick_buffer_page *prev;
}rebrick_buffer_page_t;


public_ typedef struct rebrick_buffer{
   base_object();
   public_ readonly_ rebrick_buffer_page_t *head_page;

}rebrick_buffer_t;


int32_t rebrick_buffer_new(rebrick_buffer_t **buffer,uint8_t *buf,size_t len);


/**
 * @brief destroys a buffer
 *
 * @param buffer
 * @return int32_t return REBRICK_SUCCESS otherwise error
 */
int32_t rebrick_buffer_destroy(rebrick_buffer_t *buffer);

/**
 * @brief add a new buffer to head of buffers
 *
 * @param buffer
 * @param buf
 * @param len
 * @return int32_t
 */
int32_t rebrick_buffer_add(rebrick_buffer_t *buffer,uint8_t *buf,size_t len);




/**
 * @brief removes a part of buffer
 *
 * @param buffer
 * @param start
 * @param count
 * @return int32_t
 */
int32_t rebrick_buffer_remove(rebrick_buffer_t *buffer,size_t start,size_t count);


/**
 * @brief returns total sizeof buffer
 *
 * @param buffer
 * @return int32_t <0 means error otherwise total length of buffer in bytes
 */
int32_t rebrick_buffer_total_len(rebrick_buffer_t *buffer);









#endif