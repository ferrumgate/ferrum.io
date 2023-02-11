#!/bin/bash
#sudo service apache2 stop
mkdir -p /tmp/nginx
docker stop nginx-ssl
#mkdir -p /tmp/test6
#dd if=/dev/zero of=/tmp/test6/10G bs=10M count=1024
cp nginx_data/* /tmp/test6/
docker run --name nginx-ssl --rm -d -ti \
  -p 80:80 \
  -p 8080:8080 \
  -p 443:443 \
  -e SSLKEYLOGFILE=/tmp/ssl.log \
  -v /tmp/nginx:/tmp \
  -v $PWD/nginxconfig:/etc/nginx \
  -v /tmp/test6:/var/www/example.com \
  nginx
