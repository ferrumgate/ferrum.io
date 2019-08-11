#!/bin/bash
docker run \
  --restart on-failure \
  -p 80:80 \
  -p 443:443 \
  -v $PWD/nginxconfig:/etc/nginx \
  -v $PWD/nginx_data:/var/www/example.com \
  nginx