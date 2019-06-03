#!/bin/bash
ulimit -c unlimited
sh -c "echo core-%e-%t-%s > /proc/sys/kernel/core_pattern"
LD_LIBRARY_PATH=./external/libs/lib LISTEN_PORT=9090 LISTEN_FAMILY=IPV4 BACKENDS=deneme:192.168.30.3:53,two:192.168.1.1:5353 ./src/dns.router