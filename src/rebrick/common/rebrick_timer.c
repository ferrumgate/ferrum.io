#include "rebrick_timer.h"

typedef struct rebrick_timer_private {
  base_object();

} rebrick_timer_private_t;

static void timer_callback(uv_timer_t *handle) {
  char current_time_str[32] = {0};
  unused(current_time_str);
  rebrick_timer_t *prv = cast(handle->data, rebrick_timer_t *);
  if (prv && prv->callback)
    prv->callback(prv->callback_data);
}

int32_t rebrick_timer_new(rebrick_timer_t **timer, rebrick_timer_callback_t callback, void *data, uint32_t milisecond, int32_t start_immedialyt) {
  char current_time_str[32] = {0};
  unused(current_time_str);
  int32_t result;
  if (!timer || !callback | !milisecond) {
    rebrick_log_fatal("timer, callback or milisecond is null\n");
    return REBRICK_ERR_BAD_ARGUMENT;
  }

  rebrick_timer_t *tmp = new1(rebrick_timer_t);
  constructor(tmp, rebrick_timer_t);

  result = uv_timer_init(uv_default_loop(), &(tmp->timer));

  if (result < 0) {

    rebrick_log_fatal("init timer failed:%s\n", uv_strerror(result));
    rebrick_free(tmp);

    return REBRICK_ERR_UV + result;
  }

  tmp->callback = callback;
  tmp->callback_data = data;
  tmp->milisecond = milisecond;

  *timer = tmp;
  tmp->timer.data = tmp;
  if (start_immedialyt) {
    result = uv_timer_start(&tmp->timer, timer_callback, tmp->milisecond, tmp->milisecond);
    if (result < 0) {

      rebrick_log_fatal("start timer failed:%s\n", uv_strerror(result));
      rebrick_free(tmp);

      return REBRICK_ERR_UV + result;
    }
    tmp->is_started = 1;
  }
  return REBRICK_SUCCESS;
}

int32_t rebrick_timer_start(rebrick_timer_t *timer) {
  char current_time_str[32] = {0};
  unused(current_time_str);
  int32_t result;
  if (!timer) {
    rebrick_log_fatal("timer or private is null\n");
    return REBRICK_ERR_BAD_ARGUMENT;
  }

  if (timer->is_started)
    return REBRICK_SUCCESS;

  result = uv_timer_start(&timer->timer, timer_callback, timer->milisecond, timer->milisecond);
  if (result < 0) {

    rebrick_log_fatal("start timer failed:%s\n", uv_strerror(result));

    return REBRICK_ERR_UV + result;
  }
  timer->is_started = 1;
  return REBRICK_SUCCESS;
}
int32_t rebrick_timer_stop(rebrick_timer_t *timer) {
  char current_time_str[32] = {0};
  unused(current_time_str);
  int32_t result;
  rebrick_log_debug("timer is stoping\n");
  if (!timer) {
    rebrick_log_fatal("timer or private is null\n");
    return REBRICK_ERR_BAD_ARGUMENT;
  }

  if (!timer->is_started)
    return REBRICK_SUCCESS;

  result = uv_timer_stop(&timer->timer);
  if (result < 0) {

    rebrick_log_fatal("start timer failed:%s\n", uv_strerror(result));

    return REBRICK_ERR_UV + result;
  }
  timer->is_started = 0;
  return REBRICK_SUCCESS;
}
static void on_timer_close(uv_handle_t *handle) {
  uv_timer_t *timer = cast(handle, uv_timer_t *);
  if (timer->data)
    rebrick_free(timer->data);
}
int32_t rebrick_timer_destroy(rebrick_timer_t *timer) {

  rebrick_log_debug("timer is destroying\n");
  if (timer) {

    if (timer->is_started) {
      uv_timer_stop(&timer->timer);
    }

    uv_close(cast(&timer->timer, uv_handle_t *), on_timer_close);
  }

  return REBRICK_SUCCESS;
}
