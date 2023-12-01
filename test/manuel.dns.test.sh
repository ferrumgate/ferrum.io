#!/bin/bash
while read -r line; do
    echo -n $line " "
    dig +short $line @172.28.28.1 || true
    echo
    sleep 1
done <"./data/top1m.list"
