#include "rebrick_timer.h"

typedef struct rebrick_timer_private
{
    base_object();
    rebrick_timer_callback_t callback;
    void *callback_data;
    int32_t milisecond;

    uv_timer_t timer;
    int32_t is_started;

} rebrick_timer_private_t;

static void timer_callback(uv_timer_t *handle)
{
    char current_time_str[32] = {0};
    unused(current_time_str);
    rebrick_timer_private_t *prv = cast(handle->data, rebrick_timer_private_t *);
    //rebrick_log_debug("timer is firing\n");
    if (prv && prv->callback)
        prv->callback(prv->callback_data);
}

int32_t rebrick_timer_new(rebrick_timer_t **timer, rebrick_timer_callback_t callback, void *data, uint32_t milisecond, int32_t start_immedialyt)
{
    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;
    if (!timer || !callback | !milisecond)
    {
        rebrick_log_fatal("timer, callback or milisecond is null\n");
        return REBRICK_ERR_BAD_ARGUMENT;
    }

    rebrick_timer_t *tmp = new (rebrick_timer_t);
    constructor(tmp,rebrick_timer_t);

    rebrick_timer_private_t *prv_data = new (rebrick_timer_private_t);
    constructor(prv_data,rebrick_timer_private_t);

    result = uv_timer_init(uv_default_loop(), &prv_data->timer);

    if (result < 0)
    {

        rebrick_log_fatal("init timer failed:%s\n", uv_strerror(result));
        free(tmp);
        free(prv_data);
        return REBRICK_ERR_UV + result;
    }


    prv_data->callback = callback;
    prv_data->callback_data = data;
    prv_data->milisecond = milisecond;
    tmp->private_data = prv_data;
    *timer = tmp;
    prv_data->timer.data = prv_data;
    if (start_immedialyt)
    {
        result = uv_timer_start(&prv_data->timer, timer_callback, prv_data->milisecond, prv_data->milisecond);
        if (result < 0)
        {

            rebrick_log_fatal("start timer failed:%s\n", uv_strerror(result));
            free(tmp);
            free(prv_data);
            return REBRICK_ERR_UV + result;
        }
        prv_data->is_started = 1;
    }
    return REBRICK_SUCCESS;
}

int32_t rebrick_timer_start(rebrick_timer_t *timer)
{
    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;
    if (!timer || !timer->private_data)
    {
        rebrick_log_fatal("timer or private is null\n");
        return REBRICK_ERR_BAD_ARGUMENT;
    }

    rebrick_timer_private_t *prv = cast(timer->private_data, rebrick_timer_private_t *);
    if (prv->is_started)
        return REBRICK_SUCCESS;

    result = uv_timer_start(&prv->timer, timer_callback, prv->milisecond, prv->milisecond);
    if (result < 0)
    {

        rebrick_log_fatal("start timer failed:%s\n", uv_strerror(result));

        return REBRICK_ERR_UV + result;
    }
    prv->is_started = 1;
    return REBRICK_SUCCESS;
}
int32_t rebrick_timer_stop(rebrick_timer_t *timer)
{
    char current_time_str[32] = {0};
    unused(current_time_str);
    int32_t result;
    rebrick_log_debug("timer is stoping\n");
    if (!timer || !timer->private_data)
    {
        rebrick_log_fatal("timer or private is null\n");
        return REBRICK_ERR_BAD_ARGUMENT;
    }

    rebrick_timer_private_t *prv = cast(timer->private_data, rebrick_timer_private_t *);
    if (!prv->is_started)
        return REBRICK_SUCCESS;

    result = uv_timer_stop(&prv->timer);
    if (result < 0)
    {

        rebrick_log_fatal("start timer failed:%s\n",uv_strerror(result));

        return REBRICK_ERR_UV + result;
    }
    prv->is_started = 0;
    return REBRICK_SUCCESS;
}
int32_t rebrick_timer_destroy(rebrick_timer_t *timer)
{
    char current_time_str[32] = {0};
    unused(current_time_str);
    //int32_t result;
    rebrick_log_debug("timer is destroying\n");
    if (timer)
    {
        if (timer->private_data)
        {
            rebrick_timer_private_t *prv = cast(timer->private_data, rebrick_timer_private_t *);
            if (prv->is_started)
            {
                uv_timer_stop(&prv->timer);
            }

            free(timer->private_data);
        }
        free(timer);
    }

    return REBRICK_SUCCESS;
}
