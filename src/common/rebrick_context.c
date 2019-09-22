#include "rebrick_context.h"

int32_t rebrick_context_new(rebrick_context_t **context, rebrick_config_t *config, rebrick_metrics_t *metrics)
{
    char current_time_str[32] = {0};
    unused(current_time_str);
    rebrick_context_t *tmp = new (rebrick_context_t);
    constructor(tmp, rebrick_context_t);

    tmp->config = config;
    tmp->metrics = metrics;

    *context = tmp;
    return REBRICK_SUCCESS;
}

void rebrick_context_destroy(rebrick_context_t *context)
{
    if (context)
        free(context);
}
