#include "rebrick_metrics.h"

int32_t rebrick_metrics_new(rebrick_metrics_t **metrics)
{
    char current_time_str[32] = {0};

    unused(current_time_str);

    rebrick_metrics_t *tmp;
    tmp = new (rebrick_metrics_t);
    constructor(tmp, rebrick_metrics_t);

    tmp->start_time = rebrick_util_micro_time();
    *metrics = tmp;

    return REBRICK_SUCCESS;
}

void rebrick_metrics_destroy(rebrick_metrics_t *metrics)
{

    if (metrics)
    {
        free(metrics);
    }
}

int32_t rebrick_metrics_tostring(const rebrick_metrics_t *metrics, char buffer[REBRICK_METRICS_MAX_STR_LEN])
{
    fill_zero(buffer, REBRICK_METRICS_MAX_STR_LEN);
    int32_t result = snprintf(buffer, REBRICK_METRICS_MAX_STR_LEN, "start_time:%" PRId64 "\n\
    current_time:%" PRId64 "\n\
    received_total:%" PRId64 "\n\
    received_error_total:%" PRId64 "\n\
    received_success_total:%" PRId64 "\n\
    forward_total:%" PRId64 "\n\
    forward_error_total:%" PRId64 "\n\
    forward_success_total:%" PRId64 "\n",
                              metrics->start_time, metrics->current_time, metrics->received_total, metrics->received_error_total, metrics->received_success_total,
                              metrics->forward_total, metrics->forward_error_total, metrics->forward_success_total);
    if (result < 0)
        return REBRICK_ERR_SPRINTF;
    return result;
}