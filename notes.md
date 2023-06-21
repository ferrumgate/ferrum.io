
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

# dns test 2

sudo hping3 $HOST -p $PORT --udp -V -d 15 --flood // 3 seconds
