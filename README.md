# About

ferrum.io is an open source network proxy library(tcp,udp,ssl,http,https,grpc support), for implementing services in ferrumgate zero trust framework

## Prerequities

under external folder, there are some libs like libuv for async I/O,
and for unit testing cmock project,
run prepare.libs.sh script, for preparing compile environment
then install
> install libnetfilter-conntrack-dev
>
> install conntrack

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

### DNS Protocol Checking Steps

make lmdb for compile

for starting application

```sh
    sudo LD_LIBRARY_PATH=$(pwd)/external/libs/lib  ./test/ferrum.io.lmdb /tmp/dns track list
```

- invalid dns packet #test1

    echo -n "hello" | nc -4u $HOST $PORT

- query ends with root fqdn #test2

    dig "www.ferrumgate.zero" @$HOST -p$PORT

- query not A or AAAA #test3

    dig mx ferrumgate.com @$HOST -p$PORT

- user parse not valid #test4

    sudo LD_LIBRARY_PATH=$(pwd)/external/libs/lib  ./test/ferrum.io.lmdb /tmp/dns track put /track/id/0/data "userIds:abo
groupIds"
    dig "www.ferrumgate.com" @$HOST -p$PORT

- user not found #test5

    sudo LD_LIBRARY_PATH=$(pwd)/external/libs/lib  ./test/ferrum.io.lmdb /tmp/dns track del /track/id/0/data
    dig +tries=1 +timeout=3 "www.ferrumgate.com" @$HOST -p$PORT

- authz user parse not valid #test6

    sudo LD_LIBRARY_PATH=$(pwd)/external/libs/lib  ./test/ferrum.io.lmdb /tmp/dns track put /track/id/0/data "userId=\"abc\"
groupIds=\",def,ghi,\""
    sudo LD_LIBRARY_PATH=$(pwd)/external/libs/lib  ./test/ferrum.io.lmdb /tmp/dns authz put /authz/service/id/mysqlservice/user/list "'[rules2]"
    dig +tries=1 +timeout=3 "www.ferrumgate.com" @$HOST -p$PORT

- authz user not found #test 7

    sudo LD_LIBRARY_PATH=$(pwd)/external/libs/lib  ./test/ferrum.io.lmdb /tmp/dns track put /track/id/0/data "userId=\"abc\"
groupIds=\",def,ghi,\""
    sudo LD_LIBRARY_PATH=$(pwd)/external/libs/lib  ./test/ferrum.io.lmdb /tmp/dns authz put /authz/service/id/mysqlservice/user/list "[rules2]"
    dig +tries=1 +timeout=3 "www.ferrumgate.com" @$HOST -p$PORT

- authz id absent #test 8x

    sudo LD_LIBRARY_PATH=$(pwd)/external/libs/lib  ./test/ferrum.io.lmdb /tmp/dns track put /track/id/0/data "userId=\"abc\"
groupIds=\",def,ghi,\""
    sudo LD_LIBRARY_PATH=$(pwd)/external/libs/lib  ./test/ferrum.io.lmdb /tmp/dns authz put /authz/service/id/mysqlservice/user/list "[[rules]]
id2=\"ttyy\"
userOrgroupIds=\"abc\""
    dig +tries=1 +timeout=3 "www.ferrumgate.com" @$HOST -p$PORT

- authz id founded and no authz rule founded #test 9x

    sudo LD_LIBRARY_PATH=$(pwd)/external/libs/lib  ./test/ferrum.io.lmdb /tmp/dns track put /track/id/0/data "userId=\"abc\"
groupIds=\",def,ghi,\""
    sudo LD_LIBRARY_PATH=$(pwd)/external/libs/lib  ./test/ferrum.io.lmdb /tmp/dns authz put /authz/service/id/mysqlservice/user/list "[[rules]]
id=\"ttyy\"
userOrgroupIds=\"abc\""
    sudo LD_LIBRARY_PATH=$(pwd)/external/libs/lib  ./test/ferrum.io.lmdb /tmp/dns authz del /authz/id/ttyy
    dig +tries=1 +timeout=3 "www.ferrumgate.com" @$HOST -p$PORT

  - authz rule parse #test 10x

    sudo LD_LIBRARY_PATH=$(pwd)/external/libs/lib  ./test/ferrum.io.lmdb /tmp/dns track put /track/id/0/data "userId=\"abc\"
groupIds=\",def,ghi,\""
    sudo LD_LIBRARY_PATH=$(pwd)/external/libs/lib  ./test/ferrum.io.lmdb /tmp/dns authz put /authz/service/id/mysqlservice/user/list "[[rules]]
id=\"ttyy\"
userOrgroupIds=\"abc\""
    sudo LD_LIBRARY_PATH=$(pwd)/external/libs/lib  ./test/ferrum.io.lmdb /tmp/dns authz put /authz/id/ttyy "
    id=\"ttyy\"
    [fqdnIntelligence]]"

    dig +tries=1 +timeout=3 "www.ferrumgate.com" @$HOST -p$PORT

  - authz rule parse #test 11x

    sudo LD_LIBRARY_PATH=$(pwd)/external/libs/lib  ./test/ferrum.io.lmdb /tmp/dns track put /track/id/0/data "userId=\"abc\"
groupIds=\",def,ghi,\""
    sudo LD_LIBRARY_PATH=$(pwd)/external/libs/lib  ./test/ferrum.io.lmdb /tmp/dns authz put /authz/service/id/mysqlservice/user/list "[[rules]]
id=\"ttyy\"
userOrgroupIds=\"abc\""
    sudo LD_LIBRARY_PATH=$(pwd)/external/libs/lib  ./test/ferrum.io.lmdb /tmp/dns authz put /authz/id/ttyy "
    id=\"ttyy\"
    [fqdnIntelligence]
    ignoreFqdns=\",ferrumgate.com,\"
    "

    dig +tries=1 +timeout=3 "www.ferrumgate.com" @$HOST -p$PORT

    - authz rule parse #test 12x

    sudo LD_LIBRARY_PATH=$(pwd)/external/libs/lib  ./test/ferrum.io.lmdb /tmp/dns track put /track/id/0/data "userId=\"abc\"
groupIds=\",def,ghi,\""
    sudo LD_LIBRARY_PATH=$(pwd)/external/libs/lib  ./test/ferrum.io.lmdb /tmp/dns authz put /authz/service/id/mysqlservice/user/list "[[rules]]
id=\"ttyy\"
userOrgroupIds=\"abc\""
    sudo LD_LIBRARY_PATH=$(pwd)/external/libs/lib  ./test/ferrum.io.lmdb /tmp/dns authz put /authz/id/ttyy "
    id=\"ttyy\"
    [fqdnIntelligence]
    ignoreFqdns=\",,\"
"

    dig +tries=1 +timeout=3 "www.ferrumgate.com" @$HOST -p$PORT
