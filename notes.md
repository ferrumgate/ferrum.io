
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
