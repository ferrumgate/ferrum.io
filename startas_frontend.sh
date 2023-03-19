ulimit -c unlimited
sudo sh -c "echo /tmp/core-%e-%t-%s > /proc/sys/kernel/core_pattern"
mkdir -p /tmp/test4
sudo LOG_LEVEL=info \
    REDIS_HOST=localhost:6379 \
    RAW_DESTINATION_HOST=1.1.1.1 \
    RAW_DESTINATION_TCP_PORT=53 RAW_DESTINATION_UDP_PORT=53 RAW_LISTEN_IP=192.168.88.10 \
    RAW_LISTEN_TCP_PORT=5354 RAW_LISTEN_UDP_PORT=5353 GATEWAY_ID=gateway1 \
    SERVICE_ID=mysqlservice INSTANCE_ID=randominstance POLICY_DB_FOLDER=/tmp/test4 \
    DNS_DB_FOLDER=/tmp/dns ROOT_FQDN=ferrumgate.zero PROTOCOL_TYPE=dns \
    SYSLOG_HOST=localhost:9292 DISABLE_POLICY=true \
    LD_LIBRARY_PATH=$(pwd)/external/libs/lib \
    valgrind -v --track-origins=yes --leak-check=full --show-leak-kinds=all --gen-suppressions=all --suppressions=$(pwd)/test/valgrind.options ./src/ferrum.io
