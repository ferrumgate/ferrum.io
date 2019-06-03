#!/bin/bash

hping3 localhost -p 9090 --udp -V -d 15 --flood
