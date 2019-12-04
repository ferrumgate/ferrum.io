#!/bin/bash
ulimit -c unlimited
sh -c "echo core-%e-%t-%s > /proc/sys/kernel/core_pattern"
LD_LIBRARY_PATH=../external/libs/lib ./test
