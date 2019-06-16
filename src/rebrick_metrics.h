#ifndef __REBRICK_METRICS_H__
#define __REBRICK_METRICS_H__

#include "rebrick_common.h"
#include "rebrick_log.h"
#include "rebrick_util.h"

public_ typedef struct rebrick_metrics
{
    base_class();
    public_ int64_t start_time;
    public_ int64_t current_time;
    public_ int64_t received_total;
    public_ int64_t received_error_total;
    public_ int64_t received_success_total;

    public_ int64_t forward_total;
    public_ int64_t forward_error_total;
    public_ int64_t forward_success_total;

    /* data */
} rebrick_metrics_t;

/**
 * @brief Create a roksit metrics object
 *
 * @param metrics  input pointer for creation
 * @return int32_t  <0 means error, @see REBRICK_SUCCESS
 */
int32_t rebrick_metrics_new(rebrick_metrics_t **metrics);

/**
 * @brief destroys a roksit metrics objects
 *
 */
void rebrick_metrics_destroy(rebrick_metrics_t *metrics);

/**
 * @brief max string buffer
 *
 */
#define REBRICK_METRICS_MAX_STR_LEN 512

/**
 * @brief writes metric object as string
 *
 * @param metrics
 * @param buffer
 * @return int32_t <0 means error, >0 strlen of string
 */
int32_t rebrick_metrics_tostring(const rebrick_metrics_t *metrics, char buffer[REBRICK_METRICS_MAX_STR_LEN]);

#endif