# About

ferrum.io is an open source network proxy library(tcp,udp,ssl,http,https,grpc support), for implementing services in ferrumgate zero trust framework

## Prerequities

under external folder, there are some libs like libuv for async I/O,
and for unit testing cmock project,
run prepare.libs.sh script, for preparing compile environment
then install
> apt install libnetfilter-conntrack-dev
>
> apt install conntrack

## Testing

before testing
>run test/prepare.test.sh

this scripts starts some docker servers for testing

## Compile

``` compile
make check
make
```

## Run

Preparing!!!!!

## Troubleshot

if cannot find any so library
export LD_LIBRARY_PATH=$(pwd)/../external/libs/lib

## License

[MIT](https://choosealicense.com/licenses/mit/)

## troubleshot

conntrack table list
> conntrack -L|grep 8080

setting mark on conntrack
>iptables -t mangle -A INPUT -p udp --dport 8181 -j CONNMARK --set-mark 4000000000
