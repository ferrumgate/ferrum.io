#!/bin/bash
ulimit -c unlimited

echo "starting server"
cat /proc/sys/kernel/core_pattern
mkdir -p /tmp/fast.server/archive

echo "***************ip address**************"
ip a
echo "***************************************"
echo $(pwd)

OPT_REDIS_HOST=localhost
if [ ! -z "$REDIS_HOST" ]; then
    OPT_REDIS_HOST=$REDIS_HOST
fi
echo "redis host $OPT_REDIS_HOST"

OPT_LOG_LEVEL="INFO"
if [ ! -z "$LOG_LEVEL" ]; then
    OPT_LOG_LEVEL=$LOG_LEVEL
fi
echo "log level $OPT_REDIS_HOST"

OPT_RAW_DESTINATION_HOST=""
if [ ! -z "$RAW_DESTINATION_HOST" ]; then
    OPT_RAW_DESTINATION_HOST=$RAW_DESTINATION_HOST
fi
echo "raw destination $OPT_RAW_DESTINATION_HOST"

OPT_RAW_DESTINATION_TCP_PORT=""
if [ ! -z "$RAW_DESTINATION_TCP_PORT" ]; then
    OPT_RAW_DESTINATION_TCP_PORT=$RAW_DESTINATION_TCP_PORT
fi
echo "raw destination tcp port $OPT_RAW_DESTINATION_TCP_PORT"

OPT_RAW_DESTINATION_UDP_PORT=""
if [ ! -z "$RAW_DESTINATION_UDP_PORT" ]; then
    OPT_RAW_DESTINATION_UDP_PORT=$RAW_DESTINATION_UDP_PORT
fi
echo "raw destination udp port $OPT_RAW_DESTINATION_UDP_PORT"

OPT_RAW_LISTEN_IP=""
if [ ! -z "$RAW_LISTEN_IP" ]; then
    OPT_RAW_LISTEN_IP=$RAW_LISTEN_IP
fi
echo "raw listen ip $OPT_RAW_LISTEN_IP"

OPT_RAW_LISTEN_TCP_PORT=""
if [ ! -z "$RAW_LISTEN_TCP_PORT" ]; then
    OPT_RAW_LISTEN_TCP_PORT=$RAW_LISTEN_TCP_PORT
fi
echo "raw listen tcp port $OPT_RAW_LISTEN_TCP_PORT"

OPT_RAW_LISTEN_UDP_PORT=""
if [ ! -z "$RAW_LISTEN_UDP_PORT" ]; then
    OPT_RAW_LISTEN_UDP_PORT=$RAW_LISTEN_UDP_PORT
fi
echo "raw listen udp port $OPT_RAW_LISTEN_UDP_PORT"

OPT_HOST_ID=""
if [ ! -z "$HOST_ID" ]; then
    OPT_HOST_ID=$HOST_ID
fi
echo "host id $OPT_HOST_ID"

OPT_SERVICE_ID=""
if [ ! -z "$SERVICE_ID" ]; then
    OPT_SERVICE_ID=$SERVICE_ID
fi
echo "service id $OPT_SERVICE_ID"

OPT_INSTANCE_ID=""
if [ ! -z "$INSTANCE_ID" ]; then
    OPT_INSTANCE_ID=$INSTANCE_ID
fi
echo "instance id $OPT_INSTANCE_ID"

OPT_=""
if [ ! -z "$" ]; then
    OPT_=$
fi
#echo " $OPT_"

#OPT_INSTANCE_ID=$(cat /dev/urandom | tr -dc '[:alnum:]' | fold -w ${1:-12} | head -n 1)

LD_LIBRARY_PATH="/ferrum.io/external/libs/lib" \
    LOG_LEVEL=$OPT_LOG_LEVEL \
    REDIS_HOST=$OPT_REDIS_HOST \
    RAW_DESTINATION_HOST=$OPT_RAW_DESTINATION_HOST \
    RAW_DESTINATION_UDP_PORT=$OPT_RAW_DESTINATION_UDP_PORT \
    RAW_DESTINATION_TCP_PORT=$OPT_RAW_DESTINATION_TCP_PORT \
    RAW_LISTEN_IP=$OPT_RAW_LISTEN_IP \
    RAW_LISTEN_TCP_PORT=$OPT_RAW_LISTEN_TCP_PORT \
    RAW_LISTEN_UDP_PORT=$OPT_RAW_LISTEN_UDP_PORT \
    HOST_ID=$OPT_HOST_ID \
    SERVICE_ID=$OPT_SERVICE_ID \
    INSTANCE_ID=$OPT_INSTANCE_ID \
    ./src/ferrum.io

if ls /ferrum.io/src/core* 1>/dev/null 2>&1; then
    folder=$(((RANDOM % 1000000) + 1))
    mkdir -p /var/lib/ferrum/ferrum.io/$folder
    cp -r /ferrum.io/* /var/lib/ferrum/ferrum.io/$folder
fi

echo "finished server"
