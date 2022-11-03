#!/usr/bin/env bash
PROD="FALSE"
while getopts p flag; do
    case "${flag}" in
    p) PROD="TRUE" ;;
    esac
done

set -e
TMPFOLDER=/tmp/uv
CURRENTFOLDER=$(pwd)
rm -rf $TMPFOLDER
mkdir -p $TMPFOLDER

DESTFOLDER=$(pwd)/libs

######## install libuv ###############
cp libuv-v1.44.2.tar.gz $TMPFOLDER

echo $DESTFOLDER
cd $TMPFOLDER
tar zxvf libuv-v1.44.2.tar.gz
cd libuv-v1.44.2
sh autogen.sh
./configure --prefix=$DESTFOLDER

make
#make check
make install

######## install cmocka ############
cd $CURRENTFOLDER
cp cmocka-1.1.5.tar.xz $TMPFOLDER
cd $TMPFOLDER
tar xvf cmocka-1.1.5.tar.xz
cd cmocka-1.1.5
rm -rf CMakeCache.txt
mkdir -p build
cd build
cmake -DCMAKE_INSTALL_PREFIX=$DESTFOLDER -DCMAKE_BUILD_TYPE=Debug ../
make
make install

######## install openssl #################
cd $CURRENTFOLDER
cp openssl-1.1.1q.tar.gz $TMPFOLDER
DESTFOLDER=$(pwd)/libs
cd $TMPFOLDER

tar xvf openssl-1.1.1q.tar.gz
cd openssl-1.1.1q
./config --prefix=$DESTFOLDER shared zlib
make depend
make all
make install_sw

###### install nghttp2  ################
cd $CURRENTFOLDER
cp nghttp2-1.50.0.tar.gz /tmp/uv
DESTFOLDER=$(pwd)/libs
cd $TMPFOLDER

tar xvf nghttp2-1.50.0.tar.gz
cd nghttp2-1.50.0
./configure --enable-lib-only --prefix=$DESTFOLDER
make
make install

######### install hiredis ############
cd $CURRENTFOLDER
DESTFOLDER=$(pwd)/libs
cp hiredis-1.0.2.zip $TMPFOLDER
cd $TMPFOLDER
unzip hiredis-1.0.2.zip
cd hiredis-1.0.2
export PREFIX=$DESTFOLDER
make
make install

############ make ready ##############
#cd $CURRENTFOLDER
##chown -R hframed:hframed libs
