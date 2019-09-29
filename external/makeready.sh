#!/usr/bin/env bash

set -e
TMPFOLDER=/tmp/uv
CURRENTFOLDER=$(pwd)
#rm -rf $TMPFOLDER
#mkdir -p $TMPFOLDER

######## install libuv ###############
cp libuv-v1.27.0.tar.gz $TMPFOLDER
DESTFOLDER=$(pwd)/libs
echo $DESTFOLDER
cd $TMPFOLDER
tar zxvf libuv-v1.27.0.tar.gz
cd libuv-v1.27.0
sh autogen.sh
./configure --prefix=$DESTFOLDER
make
make check
make install


######## install cmocka ############
cd $CURRENTFOLDER
cp cmocka-1.1.5.tar.xz $TMPFOLDER
cd $TMPFOLDER
tar xvf cmocka-1.1.5.tar.xz
cd cmocka-1.1.5
rm CMakeCache.txt
mkdir -p build
cd build
cmake -DCMAKE_INSTALL_PREFIX=$DESTFOLDER -DCMAKE_BUILD_TYPE=Debug ../
make
make install

######## install openssl #################
cd $CURRENTFOLDER
cp openssl-1.1.1c.tar.gz $TMPFOLDER
DESTFOLDER=$(pwd)/libs
cd $TMPFOLDER

tar xvf openssl-1.1.1c.tar.gz
cd openssl-1.1.1c
./config --prefix=$DESTFOLDER shared
make depend
make all
make install_sw








############ make ready ##############
cd $CURRENTFOLDER
chown -R hframe:hframe libs
