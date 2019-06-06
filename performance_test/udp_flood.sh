#!/bin/bash

hping3 localhost -p 9090 --udp -V -d 15 --flood

#tcp test
hping3 -I lo -c 3 -S 127.0.0.1 -p 9595
