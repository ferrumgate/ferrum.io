#!/bin/bash
# docker build script

set -e

while getopts i: flag; do
    case "${flag}" in
    i) IMAGE_NAME=${OPTARG} ;;
    esac
done

#read -p 'enter version:' version
version=$(cat ./src/ferrum/ferrum.h | grep FERRUM_VERSION | cut -d' ' -f3 | tr -d '"')

# if not set
if [ -z $IMAGE_NAME ]; then
    IMAGE_NAME=ferrum.io
fi

echo $IMAGE_NAME is building
docker build -f ./dockerfile -t $IMAGE_NAME .

echo "$IMAGE_NAME:$version builded"
docker tag $IMAGE_NAME registry.ferrumgate.local/ferrumgate/$IMAGE_NAME:$version
docker tag $IMAGE_NAME registry.ferrumgate.local/ferrumgate/$IMAGE_NAME:latest
