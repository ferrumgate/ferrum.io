#!/bin/bash
sudo service apache2 stop
mkdir -p /tmp/nginx
docker run \
  --restart on-failure \
  -p 80:80 \
  -p 80s80:8080 \
  -p 443:443 \
  -e SSLKEYLOGFILE=/tmp/ssl.log \
  -v /tmp/nginx:/tmp \
  -v $PWD/nginxconfig:/etc/nginx \
  -v $PWD/nginx_data:/var/www/example.com \
  nginx
