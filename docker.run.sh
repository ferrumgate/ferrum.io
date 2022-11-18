#!/bin/bash
IP=192.168.88.10
docker run --net=host \
    -ti \
    -e LOG_LEVEL=ALL \
    -e REDIS_HOST=$IP \
    -e RAW_DESTINATION_HOST=$IP \
    -e RAW_DESTINATION_UDP_PORT=5555 \
    -e RAW_DESTINATION_TCP_PORT=80 \
    -e RAW_LISTEN_IP=$IP \
    -e RAW_LISTEN_TCP_PORT=8181 \
    -e RAW_LISTEN_UDP_PORT=8888 \
    -e GATEWAY_ID=gateway1 \
    -e SERVICE_ID=mysqlservice \
    -e INSTANCE_ID=randominstance \
    -e DISABLE_POLICY=true \
    --cap-add=NET_ADMIN \
    -v /tmp/ferrum.io:/var/lib/ferrum/ferrum.io \
    ferrum.io:latest
