#!/bin/sh
IMAGE=expressjs-testserver-for-rebrick
docker build -t $IMAGE .
docker run   -p 9090:9090 -p 5000:5000 -p 9191:9191 $IMAGE