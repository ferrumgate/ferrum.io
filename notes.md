
## performance test

hping3 localhost -p 9090 --udp -V -d 15 --flood

# tcp test

hping3 -I lo -c 3 -S 127.0.0.1 -p 9595

# netcat test

nc -v localhost 9191

# nc echo server

ncat -v -l -p 5555 -c 'while true; do read i && echo [echo] $i; done'
echo ferrum | nc -v localhost 9191

### compiler unused problem short fix

__attribute__((unused))

## core dump prepare

echo '/var/lib/ferrum/core.%e.%p' | sudo tee /proc/sys/kernel/core_pattern
/etc/sysctl.d/50-coredump.conf
kernel.core_pattern=/dev/null

## troubleshot

conntrack table list
> conntrack -L|grep 8080

setting mark on conntrack
>iptables -t mangle -A INPUT -p udp -i enp3s0 -j CONNMARK --set-mark 4000000000

### DNS Protocol Checking Steps

make lmdb for compile

for starting application

```sh
    sudo LD_LIBRARY_PATH=$(pwd)/external/libs/lib  ./test/ferrum.io.lmdb /tmp/dns track list
```

# invalid dns packet #test1

echo "press ctrl c"
    echo -n "hello" | nc -4u $HOST $PORT

# query ends with root fqdn #test2

    dig "www.ferrumgate.zero" @$HOST -p$PORT

# query not A or AAAA #test3

    dig mx ferrumgate.com @$HOST -p$PORT

# user parse not valid #test4

    sudo LD_LIBRARY_PATH=$(pwd)/external/libs/lib  ./test/ferrum.io.lmdb /tmp/dns track put /track/id/0/data "userIds:abo
groupIds"
    dig "www.ferrumgate.com" @$HOST -p$PORT
    echo "will give servfail"

# user not found #test5

    sudo LD_LIBRARY_PATH=$(pwd)/external/libs/lib  ./test/ferrum.io.lmdb /tmp/dns track del /track/id/0/data
    dig +tries=1 +timeout=3 "www.ferrumgate.com" @$HOST -p$PORT

# authz user parse not valid #test6

    sudo LD_LIBRARY_PATH=$(pwd)/external/libs/lib  ./test/ferrum.io.lmdb /tmp/dns track put /track/id/0/data "userId=\"abc\"
groupIds=\",def,ghi,\""
    sudo LD_LIBRARY_PATH=$(pwd)/external/libs/lib  ./test/ferrum.io.lmdb /tmp/dns authz put /authz/service/id/mysqlservice/user/list "'[rules2]"
    dig +tries=1 +timeout=3 "www.ferrumgate.com" @$HOST -p$PORT

# authz user not found #test 7

    sudo LD_LIBRARY_PATH=$(pwd)/external/libs/lib  ./test/ferrum.io.lmdb /tmp/dns track put /track/id/0/data "userId=\"abc\"
groupIds=\",def,ghi,\""
    sudo LD_LIBRARY_PATH=$(pwd)/external/libs/lib  ./test/ferrum.io.lmdb /tmp/dns authz put /authz/service/id/mysqlservice/user/list "[rules2]"
    dig +tries=1 +timeout=3 "www.ferrumgate.com" @$HOST -p$PORT

# authz id absent #test 8x

    sudo LD_LIBRARY_PATH=$(pwd)/external/libs/lib  ./test/ferrum.io.lmdb /tmp/dns track put /track/id/0/data "userId=\"abc\"
groupIds=\",def,ghi,\""
    sudo LD_LIBRARY_PATH=$(pwd)/external/libs/lib  ./test/ferrum.io.lmdb /tmp/dns authz put /authz/service/id/mysqlservice/user/list "[[rules]]
id2=\"ttyy\"
userOrgroupIds=\"abc\""
    dig +tries=1 +timeout=3 "www.ferrumgate.com" @$HOST -p$PORT

# authz id founded and no authz rule founded #test 9x

    sudo LD_LIBRARY_PATH=$(pwd)/external/libs/lib  ./test/ferrum.io.lmdb /tmp/dns track put /track/id/0/data "userId=\"abc\"
groupIds=\",def,ghi,\""
    sudo LD_LIBRARY_PATH=$(pwd)/external/libs/lib  ./test/ferrum.io.lmdb /tmp/dns authz put /authz/service/id/mysqlservice/user/list "[[rules]]
id=\"ttyy\"
userOrgroupIds=\"abc\""
    sudo LD_LIBRARY_PATH=$(pwd)/external/libs/lib  ./test/ferrum.io.lmdb /tmp/dns authz del /authz/id/ttyy
    dig +tries=1 +timeout=3 "www.ferrumgate.com" @$HOST -p$PORT

# authz rule parse #test 10x

    sudo LD_LIBRARY_PATH=$(pwd)/external/libs/lib  ./test/ferrum.io.lmdb /tmp/dns track put /track/id/0/data "userId=\"abc\"
groupIds=\",def,ghi,\""
    sudo LD_LIBRARY_PATH=$(pwd)/external/libs/lib  ./test/ferrum.io.lmdb /tmp/dns authz put /authz/service/id/mysqlservice/user/list "[[rules]]
id=\"ttyy\"
userOrgroupIds=\"abc\""
    sudo LD_LIBRARY_PATH=$(pwd)/external/libs/lib  ./test/ferrum.io.lmdb /tmp/dns authz put /authz/id/ttyy "
    id=\"ttyy\"
    [fqdnIntelligence]]"

    dig +tries=1 +timeout=3 "www.ferrumgate.com" @$HOST -p$PORT

# authz rule parse #test 11x

    sudo LD_LIBRARY_PATH=$(pwd)/external/libs/lib  ./test/ferrum.io.lmdb /tmp/dns track put /track/id/0/data "userId=\"abc\"
groupIds=\",def,ghi,\""
    sudo LD_LIBRARY_PATH=$(pwd)/external/libs/lib  ./test/ferrum.io.lmdb /tmp/dns authz put /authz/service/id/mysqlservice/user/list "[[rules]]
id=\"ttyy\"
userOrgroupIds=\"abc\""
    sudo LD_LIBRARY_PATH=$(pwd)/external/libs/lib  ./test/ferrum.io.lmdb /tmp/dns authz put /authz/id/ttyy "
    id=\"ttyy\"
    [fqdnIntelligence]
    ignoreFqdns=\",ferrumgate2.com,\"
    ignoreLists=\",abc,\"
    "

    dig +tries=1 +timeout=3 "www.ferrumgate.com" @$HOST -p$PORT

# authz rule parse #test 12x

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

# dns test business

sudo hping3 $HOST -p $PORT --udp -V -d 15 --flood // 3 seconds

- add redis fqdn list

    docker exec -ti $redis /bin/bash

    add redis

        sadd /fqdn/ferrumgate.com/list abc def

    cd /tmp/top1m

## add user

sudo LD_LIBRARY_PATH=$(pwd)/external/libs/lib  ./test/ferrum.io.lmdb /tmp/dns track put /track/id/0/data "userId=\"abc\"
groupIds=\",def,ghi,\""

## add service

    sudo LD_LIBRARY_PATH=$(pwd)/external/libs/lib  ./test/ferrum.io.lmdb /tmp/dns authz put /authz/service/id/mysqlservice/user/list "[[rules]]
id=\"ttyy\"
userOrgroupIds=\"abc\""

## test ignore fqdn list, you will see on screen "in ignore list"

  sudo LD_LIBRARY_PATH=$(pwd)/external/libs/lib  ./test/ferrum.io.lmdb /tmp/dns authz put /authz/id/ttyy "
    id=\"ttyy\"
    [fqdnIntelligence]
    ignoreFqdns=\",ferrumgate.com,\"
"
dig "www.ferrumgate.com" @$HOST -p$PORT

## test white fqdn list, you will see on screen "in white list"

  sudo LD_LIBRARY_PATH=$(pwd)/external/libs/lib  ./test/ferrum.io.lmdb /tmp/dns authz put /authz/id/ttyy "
    id=\"ttyy\"
    [fqdnIntelligence]
    whiteFqdns=\",ferrumgate.com,\"
"
dig "www.ferrumgate.com" @$HOST -p$PORT

## test black fqdn list, you will see on scree "in black list and ip will return 0.0.0.0"

    sudo LD_LIBRARY_PATH=$(pwd)/external/libs/lib  ./test/ferrum.io.lmdb /tmp/dns authz put /authz/id/ttyy "
    id=\"ttyy\"
    [fqdnIntelligence]
    blackFqdns=\",ferrumgate.com,\"
"
dig "www.ferrumgate.com" @$HOST -p$PORT

## test ignore list id, you will see on screen "in ignore list"

    sudo LD_LIBRARY_PATH=$(pwd)/external/libs/lib  ./test/ferrum.io.lmdb /tmp/dns authz put /authz/id/ttyy "
    id=\"ttyy\"
    [fqdnIntelligence]
    ignoreLists=\",abc,\"
"
dig "www.ferrumgate.com" @$HOST -p$PORT

## test white list id, you will see on screen "in white list"

    sudo LD_LIBRARY_PATH=$(pwd)/external/libs/lib  ./test/ferrum.io.lmdb /tmp/dns authz put /authz/id/ttyy "
    id=\"ttyy\"
    [fqdnIntelligence]
    whiteLists=\",abc,\"
"
dig "www.ferrumgate.com" @$HOST -p$PORT

## test black list, you will see on screen "in black list, and ip 0.0.0.0"

    sudo LD_LIBRARY_PATH=$(pwd)/external/libs/lib  ./test/ferrum.io.lmdb /tmp/dns authz put /authz/id/ttyy "
    id=\"ttyy\"
    [fqdnIntelligence]
    blackLists=\",abc,\"
"
dig "www.ferrumgate.com" @$HOST -p$PORT

### examples commmands

run dns
for query in $(cat top1.list); do echo $query; dig +short $query +timeout=5 @192.168.88.250 -p5656;sleep 1; done

add redis category info
for fqdn in $(cat top1m.list); do ((counter=counter+1)); if [ $(expr $counter % 2) -eq 0 ]; then redis-cli sadd /fqdn/$fqdn/list abc def; echo $counter; fi; done
