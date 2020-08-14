#ifndef __REBRICK_BUFFER_H__
#define __REBRICK_BUFFER_H__

#include "rebrick_common.h"
#include "rebrick_log.h"
#include "../lib/utlist.h"

public_ typedef struct rebrick_buffer
{
   base_object();
   public_ readonly_ uint8_t *buf;
   public_ readonly_ size_t len;
   public_ readonly_ size_t malloc_len;
   public_ readonly_ size_t malloc_size;

} rebrick_buffer_t;

int32_t rebrick_buffer_new(rebrick_buffer_t **buffer, uint8_t *buf, size_t len, size_t mallocsize);

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
int32_t rebrick_buffer_add(rebrick_buffer_t *buffer, uint8_t *buf, size_t len);

/**
 * @brief removes a part of buffer
 *
 * @param buffer
 * @param start
 * @param count
 * @return int32_t
 */
int32_t rebrick_buffer_remove(rebrick_buffer_t *buffer, size_t start, size_t count);

#endif