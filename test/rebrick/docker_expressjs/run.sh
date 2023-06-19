#!/bin/sh
IMAGE=expressjs-testserver-for-rebrick
docker build -t $IMAGE .
docker stop express || true
docker run --name express --rm -d -ti -p 9090:9090 -p 9191:9191 -p 9292:9292 -p 9393:9393 $IMAGE
