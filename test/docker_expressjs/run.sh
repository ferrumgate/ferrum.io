#!/bin/sh
IMAGE=expressjs-testserver-for-rebrick
docker build -t $IMAGE .
docker run   -p 9090:9090 -p 3000:3000 $IMAGE