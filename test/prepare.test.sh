#!/bin/bash

if [ ! -f ./test/rebrick/docker_ssl/nginx_data/100m.ignore.txt ]; then
    dd if=/dev/zero of=test/rebrick/docker_ssl/nginx_data/100m.ignore.txt bs=1M count=100
fi

mkdir -p /tmp/top1m
if [ -f "$(pwd)/test/data/top1m.list" ]; then

    cp "$(pwd)/test/data/top1m.list" /tmp/top1m/
    echo "copied data"
fi

echo "starting bind"
CURRENT_FOLDER=$(pwd)
echo "$CURRENT_FOLDER"
cd "$CURRENT_FOLDER/test/rebrick/docker_bind" || exit 1
bash run.sh

echo "$CURRENT_FOLDER"
echo "starting expressjs"
cd "$CURRENT_FOLDER/test/rebrick/docker_expressjs" || exit 1
bash run.sh

echo "$CURRENT_FOLDER"
echo "starting nginx ssl"
cd "$CURRENT_FOLDER/test/rebrick/docker_ssl" || exit 1
bash run.sh

docker stop redis
docker run --name redis -v /tmp/top1m:/tmp/top1m --rm -d -ti -p 6379:6379 redis

docker stop redis_local
docker run --name redis_local --rm -d -ti -p 6380:6379 redis
