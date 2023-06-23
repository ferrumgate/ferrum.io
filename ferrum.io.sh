#!/bin/bash
ulimit -c unlimited

echo "starting server"
#mkdir -p /ferrum.io/core
#echo '/ferrum.io/core/core.%e.%p' | tee /proc/sys/kernel/core_pattern
#CORE_FOLDER=$(dirname $(cat /proc/sys/kernel/core_pattern))
#echo $CORE_FOLDER
#sysctl -w kernel.core_pattern=/ferrum.io/core/core-%e.%p.%h.%t

echo "***************ip address**************"
ip a
echo "***************************************"
echo $(pwd)

OPT_REDIS_HOST=localhost
if [ ! -z "$REDIS_HOST" ]; then
    OPT_REDIS_HOST=$REDIS_HOST
fi
echo "redis host $OPT_REDIS_HOST"

OPT_SYSLOG_HOST=localhost:9292
if [ ! -z "$SYSLOG_HOST" ]; then
    OPT_SYSLOG_HOST=$SYSLOG_HOST
fi
echo "syslog host $OPT_SYSLOG_HOST"

OPT_LOG_LEVEL="info"
if [ ! -z "$LOG_LEVEL" ]; then
    OPT_LOG_LEVEL=$LOG_LEVEL
fi
echo "log level $OPT_LOG_LEVEL"

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

OPT_GATEWAY_ID=""
if [ ! -z "$GATEWAY_ID" ]; then
    OPT_GATEWAY_ID=$GATEWAY_ID
fi
echo "gateway id $OPT_GATEWAY_ID"

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

OPT_DB_FOLDER=""
if [ ! -z "$DB_FOLDER" ]; then
    OPT_DB_FOLDER=$DB_FOLDER
    mkdir -p $OPT_DB_FOLDER
fi
echo "db folder $OPT_DB_FOLDER"

OPT_POLICY_DB_FOLDER="/var/lib/ferrumgate/policy"
if [ ! -z "$POLICY_DB_FOLDER" ]; then
    OPT_POLICY_DB_FOLDER=$POLICY_DB_FOLDER
fi
echo "policy db folder $OPT_POLICY_DB_FOLDER"
mkdir -p $OPT_POLICY_DB_FOLDER

OPT_TRACK_DB_FOLDER="/var/lib/ferrumgate/track"
if [ ! -z "$TRACK_DB_FOLDER" ]; then
    OPT_TRACK_DB_FOLDER=$TRACK_DB_FOLDER
fi
echo "track db folder $OPT_TRACK_DB_FOLDER"
mkdir -p $OPT_TRACK_DB_FOLDER

OPT_AUTHZ_DB_FOLDER="/var/lib/ferrumgate/authz"
if [ ! -z "$AUTHZ_DB_FOLDER" ]; then
    OPT_AUTHZ_DB_FOLDER=$AUTHZ_DB_FOLDER
fi
echo "authz db folder $OPT_AUTHZ_DB_FOLDER"
mkdir -p $OPT_AUTHZ_DB_FOLDER

OPT_DNS_DB_FOLDER="/var/lib/ferrumgate/dns"
if [ ! -z "$DNS_DB_FOLDER" ]; then
    OPT_DNS_DB_FOLDER=$DNS_DB_FOLDER
fi
echo "dns db folder $OPT_DNS_DB_FOLDER"
mkdir -p $OPT_DNS_DB_FOLDER

OPT_SOCKET_WRITE_BUF_SIZE="524288"
if [ ! -z "$SOCKET_WRITE_BUF_SIZE" ]; then
    OPT_SOCKET_WRITE_BUF_SIZE=$SOCKET_WRITE_BUF_SIZE
fi
echo "socket write buf size $OPT_SOCKET_WRITE_BUF_SIZE"

OPT_ROOT_FQDN="ferrumgate.zero"
if [ ! -z "$ROOT_FQDN" ]; then
    OPT_ROOT_FQDN=$ROOT_FQDN
fi
echo "root fqdn $OPT_ROOT_FQDN"

OPT_=""
if [ ! -z "$" ]; then
    OPT_=$
fi
#echo " $OPT_"

#OPT_INSTANCE_ID=$(cat /dev/urandom | tr -dc '[:alnum:]' | fold -w ${1:-12} | head -n 1)

LD_LIBRARY_PATH="/ferrum.io/external/libs/lib" \
    LOG_LEVEL=$OPT_LOG_LEVEL \
    REDIS_HOST=$OPT_REDIS_HOST \
    SYSLOG_HOST=$OPT_SYSLOG_HOST \
    RAW_DESTINATION_HOST=$OPT_RAW_DESTINATION_HOST \
    RAW_DESTINATION_UDP_PORT=$OPT_RAW_DESTINATION_UDP_PORT \
    RAW_DESTINATION_TCP_PORT=$OPT_RAW_DESTINATION_TCP_PORT \
    RAW_LISTEN_IP=$OPT_RAW_LISTEN_IP \
    RAW_LISTEN_TCP_PORT=$OPT_RAW_LISTEN_TCP_PORT \
    RAW_LISTEN_UDP_PORT=$OPT_RAW_LISTEN_UDP_PORT \
    GATEWAY_ID=$OPT_GATEWAY_ID \
    SERVICE_ID=$OPT_SERVICE_ID \
    INSTANCE_ID=$OPT_INSTANCE_ID \
    SOCKET_WRITE_BUF_SIZE=$OPT_SOCKET_WRITE_BUF_SIZE \
    DB_FOLDER=$OPT_DB_FOLDER \
    POLICY_DB_FOLDER=$OPT_POLICY_DB_FOLDER \
    DNS_DB_FOLDER=$OPT_DNS_DB_FOLDER \
    TRACK_DB_FOLDER=$OPT_TRACK_DB_FOLDER \
    AUTHZ_DB_FOLDER=$OPT_AUTHZ_DB_FOLDER ./src/ferrum.io

if ls core* 1>/dev/null 2>&1; then
    folder=$(((RANDOM % 1000000) + 1))
    mkdir -p /var/lib/ferrumgate/core/$folder
    cp -r /ferrum.io/* /var/lib/ferrumgate/core/$folder
fi

echo "finished server"
