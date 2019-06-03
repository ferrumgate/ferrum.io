#ifndef __REBRICK_CONFIG_H__
#define __REBRICK_CONFIG_H__

#include "rebrick_common.h"
#include "rebrick_log.h"






enum rebrick_listen_family{
    REBRICK_IPV4=0,
    REBRICK_IPV6=1,
    ROSKIT_IPV4_IPV6=2
};

typedef struct rebrick_config
{
    /* memory leak olursa,memory dump yapıp bakıyoruz, bütün struct larda aynı property var */
    base_class();
    /*server listen port*/
    int32_t listen_port;
    /*server listen family */
    int32_t listen_family;



} rebrick_config_t;





/**
 * @brief Create a roksit config object
 *
 * @return rebrick_config_t*
 */
int32_t rebrick_config_new(rebrick_config_t **config);

/**
 * @brief destroys a config object
 *
 * @param config object
 */
void rebrick_config_destroy(rebrick_config_t *config);

#endif
