ulimit -c unlimited
sudo sh -c "echo /tmp/core-%e-%t-%s > /proc/sys/kernel/core_pattern"
mkdir -p /tmp/test4
mkdir -p /tmp/dns
mkdir -p /tmp/dns2
mkdir -p /tmp/dns3
mkdir -p /tmp/dns4

PROTOCOL_TYPE=raw

case "$1" in
--raw)
    PROTOCOL_TYPE=raw
    ;;
--dns)
    PROTOCOL_TYPE=dns
    ;;
--tproxy)
    PROTOCOL_TYPE=tproxy
    ;;

*)
    echo "Invalid protocol type. Only '--raw' or '--dns' or '--tproxy' are allowed."
    exit 1
    ;;
esac

echo "Protocol type: $PROTOCOL_TYPE"

if [ $PROTOCOL_TYPE == "dns" ]; then
    sudo LOG_LEVEL=debug \
        REDIS_HOST=127.0.0.1:6379 \
        RAW_DESTINATION_HOST=192.168.88.250 \
        RAW_DESTINATION_TCP_PORT=5555 RAW_DESTINATION_UDP_PORT=5555 RAW_LISTEN_IP=192.168.88.250 \
        RAW_LISTEN_TCP_PORT=5656 RAW_LISTEN_UDP_PORT=5656 GATEWAY_ID=gateway1 \
        SERVICE_ID=mysqlservice INSTANCE_ID=randominstance DB_FOLDER=/tmp/dns \
        POLICY_DB_FOLDER=/tmp/dns2 AUTHZ_DB_FOLDER=/tmp/dns3 TRACK_DB_FOLDER=/tmp/dns4 \
        ROOT_FQDN=ferrumgate.zero PROTOCOL_TYPE=dns \
        SYSLOG_HOST=127.0.0.1:9292 DISABLE_POLICY=true \
        LD_LIBRARY_PATH="$(pwd)/external/libs/lib" \
        valgrind -v --track-origins=yes --leak-check=full --show-leak-kinds=all --gen-suppressions=all --suppressions="$(pwd)/test/valgrind.options" ./src/ferrum.io
fi

if [ $PROTOCOL_TYPE == "tproxy" ]; then

    read -r -p "Do you want to set with iptables rules? (yes/no): " choice
    case "$choice" in
    yes | Yes | YES)
        ### first option
        # sudo iptables -t mangle -A PREROUTING -d 192.168.105.105/32 -p tcp -j TPROXY --on-port 8081 --on-ip 127.0.0.1 --tproxy-mark 0x1/0x1
        # sudo ip route add local 192.168.105.105/32 dev lo src 127.0.0.1
        # docker run -p 192.168.88.250:9095:80 nginx # this is the destination server
        ### second option
        #sudo ip addr add 192.168.105.105/32 dev lo
        #sudo iptables -t mangle -A PREROUTING -d 192.168.105.105/32 -p tcp --dport 15:65000 -j TPROXY --on-port 10 --on-ip 127.0.0.1 --tproxy-mark 0x1/0x1
        #sudo ip rule add fwmark 0x1/0x1 table 100
        #sudo ip route add local 0.0.0.0/0 dev lo table 100
        ;;
    *) ;;
    esac

    sudo LOG_LEVEL=debug \
        REDIS_HOST=127.0.0.1:6379 \
        RAW_DESTINATION_HOST=192.168.88.250 \
        RAW_DESTINATION_TCP_PORT=80 RAW_DESTINATION_UDP_PORT=80 RAW_LISTEN_IP=127.0.0.1 \
        RAW_LISTEN_TCP_PORT=8081 RAW_LISTEN_UDP_PORT=8081 GATEWAY_ID=gateway1 \
        SERVICE_ID=mysqlservice INSTANCE_ID=randominstance DB_FOLDER=/tmp/dns \
        POLICY_DB_FOLDER=/tmp/dns2 AUTHZ_DB_FOLDER=/tmp/dns3 TRACK_DB_FOLDER=/tmp/dns4 \
        ROOT_FQDN=ferrumgate.zero PROTOCOL_TYPE=tproxy \
        SYSLOG_HOST=127.0.0.1:9292 DISABLE_POLICY=true \
        LD_LIBRARY_PATH="$(pwd)/external/libs/lib" \
        ./src/ferrum.io
    #valgrind -v --track-origins=yes --leak-check=full --show-leak-kinds=all --gen-suppressions=all --suppressions="$(pwd)/test/valgrind.options" ./src/ferrum.io
fi
