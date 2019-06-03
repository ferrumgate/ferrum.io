#ifndef __REBRICK_CONTEXT_H__
#define __REBRICK_CONTEXT_H__
#include "rebrick_common.h"
#include "rebrick_config.h"
#include "rebrick_metrics.h"
#include "rebrick_log.h"

/**
 * @brief context object that holds system configration,and all static data
 *
 */
typedef struct rebrick_context
{
      base_class();
      rebrick_config_t *config;
      rebrick_metrics_t *metrics;


}rebrick_context_t;




/**
 * @brief Create a roksit default context object
 *
 * @return int32_t not 0 then error
 */
int32_t rebrick_context_new(rebrick_context_t **context,rebrick_config_t *config, rebrick_metrics_t *metrics);

void rebrick_context_destroy(rebrick_context_t *context);

#endif //
