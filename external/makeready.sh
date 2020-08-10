#!/usr/bin/env bash

set -e
TMPFOLDER=/tmp/uv
CURRENTFOLDER=$(pwd)
rm -rf $TMPFOLDER
mkdir -p $TMPFOLDER

######## install libuv ###############
cp libuv-1.38.1.tar.gz $TMPFOLDER
DESTFOLDER=$(pwd)/libs
echo $DESTFOLDER
cd $TMPFOLDER
tar zxvf libuv-1.38.1.tar.gz
cd libuv-1.38.1
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
cp openssl-1.1.1g.tar.gz $TMPFOLDER
DESTFOLDER=$(pwd)/libs
cd $TMPFOLDER

tar xvf openssl-1.1.1g.tar.gz
cd openssl-1.1.1g
./config --prefix=$DESTFOLDER shared zlib
make depend
make all
make install_sw


###### install nghttp2  ################
cd $CURRENTFOLDER
cp nghttp2-1.41.0.tar.gz /tmp/uv
DESTFOLDER=$(pwd)/libs
cd $TMPFOLDER

tar xvf nghttp2-1.41.0.tar.gz
cd nghttp2-1.41.0
./configure --enable-lib-only --prefix=$DESTFOLDER
make 
make install








############ make ready ##############
cd $CURRENTFOLDER
chown -R hframe:hframe libs

