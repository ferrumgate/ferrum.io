#include "rebrick_config.h"




int32_t rebrick_config_new(rebrick_config_t **config)
{

    char current_time_str[32] = {0};
    rebrick_config_t *tmp = new(rebrick_config_t);
    if (!tmp)
        return REBRICK_ERR_MALLOC;

    fill_zero(tmp, sizeof(rebrick_config_t));
    strcpy(tmp->type_name, "rebrick_config_t");
    char *port = getenv("LISTEN_PORT");

    rebrick_log_info("environment variable LISTEN_PORT is: %s\n", port ? port : "null");


    tmp->listen_port = 53;
    if (port)
        tmp->listen_port = atoi(port);



    tmp->listen_family = REBRICK_IPV4;
    char *listen_family = getenv("LISTEN_FAMILY");
    rebrick_log_info("environment variable LISTEN_FAMILY is: %s\n", listen_family ? listen_family : "null");

    if (listen_family)
    {


        if (strcmp(listen_family, "IPV4") == 0)
            tmp->listen_family = REBRICK_IPV4;
        if (strcmp(listen_family, "IPV6") == 0)
            tmp->listen_family = REBRICK_IPV6;
        if (strcmp(listen_family, "IPV4_IPV6") == 0)
            tmp->listen_family = REBRICK_IPV4_IPV6;
    }



    *config = tmp;
    return REBRICK_SUCCESS;
}

void rebrick_config_destroy(rebrick_config_t *config)
{
    if (config){

        free(config);
    }
}
