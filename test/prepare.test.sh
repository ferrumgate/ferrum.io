#!/bin/bash

if [ -z test/rebrick/docker_ssl/nginx_data/100m.ignore.txt ]; then
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
