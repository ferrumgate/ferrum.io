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
docker build --no-cache --progress=plain -f ./dockerfile -t $IMAGE_NAME .

echo "$IMAGE_NAME:$version builded"
docker tag $IMAGE_NAME registry.ferrumgate.zero/ferrumgate/$IMAGE_NAME:$version
docker tag $IMAGE_NAME registry.ferrumgate.zero/ferrumgate/$IMAGE_NAME:latest

while true; do
    read -p "do you want to push to local registry y/n " yn
    case $yn in
    [Yy]*)
        docker push registry.ferrumgate.zero/ferrumgate/$IMAGE_NAME:$version
        docker push registry.ferrumgate.zero/ferrumgate/$IMAGE_NAME:latest
        break
        ;;
    [Nn]*) exit ;;
    *) echo "please answer yes or no." ;;
    esac
done
