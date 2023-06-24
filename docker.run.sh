#!/bin/bash
mkdir -p /tmp/ferrum.io
IP=192.168.88.250
docker run --net=host \
    -ti \
    -e LOG_LEVEL=debug \
    -e REDIS_HOST=$IP \
    -e REDIS_INTEL_HOST=$IP \
    -e RAW_DESTINATION_HOST=$IP \
    -e RAW_DESTINATION_UDP_PORT=5555 \
    -e RAW_DESTINATION_TCP_PORT=80 \
    -e RAW_LISTEN_IP=$IP \
    -e RAW_LISTEN_TCP_PORT=8181 \
    -e RAW_LISTEN_UDP_PORT=8888 \
    -e GATEWAY_ID=gateway1 \
    -e SERVICE_ID=mysqlservice \
    -e INSTANCE_ID=randominstance \
    -e INSTANCE_ID=randominstance \
    -e DISABLE_POLICY=true \
    -e DB_FOLDER=/var/lib/ferrumgate/db \
    -e PROTOCOL_TYPE=dns \
    --cap-add=NET_ADMIN \
    -v /tmp/ferrum.io:/var/lib/ferrumgate \
    ferrum.io:latest #-v /tmp/ferrum.io:/var/lib/ferrumgate \
