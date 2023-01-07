#ifndef __REBRICK_TIMER_H__
#define __REBRICK_TIMER_H__

#include "rebrick_common.h"
#include "rebrick_log.h"

typedef int32_t (*rebrick_timer_callback_t)(void *data);

typedef struct rebrick_timer {
  base_object();
  private_ rebrick_timer_callback_t callback;
  private_ void *callback_data;
  public_ readonly_ int32_t milisecond;

  private_ uv_timer_t timer;
  public_ readonly_ int32_t is_started;

} rebrick_timer_t;

int32_t rebrick_timer_new(rebrick_timer_t **timer, rebrick_timer_callback_t callback, void *data, uint32_t milisecond, int32_t start_immediatly);
int32_t rebrick_timer_start(rebrick_timer_t *timer);
int32_t rebrick_timer_start_after(rebrick_timer_t *timer, int32_t elapsed);
int32_t rebrick_timer_stop(rebrick_timer_t *timer);
int32_t rebrick_timer_destroy(rebrick_timer_t *timer);

#endif