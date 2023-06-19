#!/bin/bash

if [ ! -f ./test/rebrick/docker_ssl/nginx_data/100m.ignore.txt ]; then
    dd if=/dev/zero of=test/rebrick/docker_ssl/nginx_data/100m.ignore.txt bs=1M count=100
fi

echo "starting bind"
CURRENT_FOLDER=$(pwd)
echo $CURRENT_FOLDER
cd $CURRENT_FOLDER/test/rebrick/docker_bind
bash run.sh

echo $CURRENT_FOLDER
echo "starting expressjs"
cd $CURRENT_FOLDER/test/rebrick/docker_expressjs
bash run.sh

echo $CURRENT_FOLDER
echo "starting nginx ssl"
cd $CURRENT_FOLDER/test/rebrick/docker_ssl
bash run.sh

docker stop redis
docker run --name redis --rm -d -ti -p 6379:6379 redis

docker stop redis_local
docker run --name redis_local --rm -d -ti -p 6380:6379 redis
