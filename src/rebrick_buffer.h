#ifndef __REBRICK_BUFFER_H__
#define __REBRICK_BUFFER_H__

#include "rebrick_common.h"
#include "rebrick_log.h"

#define REBRICK_BUFFER_DEFAULT_MALLOC_SIZE 128

public_ typedef struct rebrick_buffer{
   base_object();
   public_ readonly_ uint8_t *buf;
   public_ readonly_ size_t len;
   private_ size_t real_len;
   private_ size_t realloc_len;
}rebrick_buffer_t;



int32_t rebrick_buffer_new(rebrick_buffer_t **buffer,size_t realloc_len);

int32_t rebrick_buffer_new2(rebrick_buffer_t **buffer);
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







#endif