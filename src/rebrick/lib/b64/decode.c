
/**
 * `decode.c' - b64
 *
 * copyright (c) 2014 joseph werle
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include "b64.h"

#ifdef b64_USE_CUSTOM_MALLOC
extern void *b64_malloc(size_t);
#endif

#ifdef b64_USE_CUSTOM_REALLOC
extern void *b64_realloc(void *, size_t);
#endif

unsigned char *
b64_decode(const char *src, size_t len) {
  char current_time_str[32] = {0};
  unused(current_time_str);
  unsigned char dtable[256], *out, *pos, block[4], tmp;
  size_t i, count, olen;
  int pad = 0;

  memset(dtable, 0x80, 256);
  for (i = 0; i < sizeof(base64_table) - 1; i++)
    dtable[(int32_t)base64_table[i]] = (unsigned char)i;
  dtable['='] = 0;

  count = 0;
  for (i = 0; i < len; i++) {
    if (dtable[(int32_t)src[i]] != 0x80)
      count++;
  }

  if (count == 0 || count % 4)
    return NULL;

  olen = count / 4 * 3;
  pos = out = malloc(olen);
  if (out == NULL) {
    rebrick_log_fatal("malloc problem\n");
    exit(1);
  }

  count = 0;
  for (i = 0; i < len; i++) {
    tmp = dtable[(int32_t)src[i]];
    if (tmp == 0x80)
      continue;

    if (src[i] == '=')
      pad++;
    block[count] = tmp;
    count++;
    if (count == 4) {
      *pos++ = (block[0] << 2) | (block[1] >> 4);
      *pos++ = (block[1] << 4) | (block[2] >> 2);
      *pos++ = (block[2] << 6) | block[3];
      count = 0;
      if (pad) {
        if (pad == 1)
          pos--;
        else if (pad == 2)
          pos -= 2;
        else {
          /* Invalid padding */
          free(out);
          return NULL;
        }
        break;
      }
    }
  }

  return out;
}
