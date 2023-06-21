ulimit -c unlimited
sudo sh -c "echo /tmp/core-%e-%t-%s > /proc/sys/kernel/core_pattern"
mkdir -p /tmp/test4
sudo LOG_LEVEL=info \
    REDIS_HOST=127.0.0.1:6379 \
    RAW_DESTINATION_HOST=192.168.88.250 \
    RAW_DESTINATION_TCP_PORT=5555 RAW_DESTINATION_UDP_PORT=5555 RAW_LISTEN_IP=192.168.88.250 \
    RAW_LISTEN_TCP_PORT=5656 RAW_LISTEN_UDP_PORT=5656 GATEWAY_ID=gateway1 \
    SERVICE_ID=mysqlservice INSTANCE_ID=randominstance DB_FOLDER=/tmp/dns \
    ROOT_FQDN=ferrumgate.zero PROTOCOL_TYPE=dns \
    SYSLOG_HOST=127.0.0.1:9292 DISABLE_POLICY=true \
    LD_LIBRARY_PATH=$(pwd)/external/libs/lib \
    valgrind -v --track-origins=yes --leak-check=full --show-leak-kinds=all --gen-suppressions=all --suppressions=$(pwd)/test/valgrind.options ./src/ferrum.io
