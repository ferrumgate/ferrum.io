
/**
 * `encode.c' - b64
 *
 * copyright (c) 2014 joseph werle
 */

#include <stdio.h>
#include <stdlib.h>
#include "b64.h"

#ifdef b64_USE_CUSTOM_MALLOC
extern void *b64_malloc(size_t);
#endif

#ifdef b64_USE_CUSTOM_REALLOC
extern void *b64_realloc(void *, size_t);
#endif

char *
b64_encode(const unsigned char *src, size_t len) {
  char current_time_str[32] = {0};
  unused(current_time_str);
  unsigned char *out, *pos;
  const unsigned char *end, *in;
  size_t olen;

  olen = len * 4 / 3 + 4; /* 3-byte blocks to 4-byte */
  olen += olen / 72;      /* line feeds */
  olen++;                 /* nul termination */
  if (olen < len)
    return NULL; /* integer overflow */
  out = malloc(olen);
  if (out == NULL) {
    rebrick_log_fatal(__FILE__, __LINE__, "malloc problem\n");
    exit(1);
  }

  end = src + len;
  in = src;
  pos = out;

  while (end - in >= 3) {
    *pos++ = base64_table[in[0] >> 2];
    *pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
    *pos++ = base64_table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
    *pos++ = base64_table[in[2] & 0x3f];
    in += 3;
  }

  if (end - in) {
    *pos++ = base64_table[in[0] >> 2];
    if (end - in == 1) {
      *pos++ = base64_table[(in[0] & 0x03) << 4];
      *pos++ = '=';
    } else {
      *pos++ = base64_table[((in[0] & 0x03) << 4) |
                            (in[1] >> 4)];
      *pos++ = base64_table[(in[1] & 0x0f) << 2];
    }
    *pos++ = '=';
  }

  *pos = '\0';
  return (char *)out;
}
