ulimit -c unlimited
sudo sh -c "echo /tmp/core-%e-%t-%s > /proc/sys/kernel/core_pattern"

sudo LOG_LEVEL=warn \
    REDIS_HOST=localhost:6379 \
    RAW_DESTINATION_HOST=192.168.88.10 \
    RAW_DESTINATION_TCP_PORT=80 RAW_DESTINATION_UDP_PORT=5555 RAW_LISTEN_IP=192.168.88.10 \
    RAW_LISTEN_TCP_PORT=8181 RAW_LISTEN_UDP_PORT=8888 GATEWAY_ID=gateway1 \
    SERVICE_ID=mysqlservice INSTANCE_ID=randominstance LMDB_FOLDER=/tmp/test4 \
    SYSLOG_HOST=localhost:9292 DISABLE_POLICY=true LD_LIBRARY_PATH=$(pwd)/external/libs/lib \
    valgrind -v --track-origins=yes --leak-check=full --show-leak-kinds=all --gen-suppressions=all --suppressions=$(pwd)/test/valgrind.options ./src/ferrum.io
