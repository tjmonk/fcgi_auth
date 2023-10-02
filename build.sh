#!/bin/sh

sudo apt-get install gcc make m4 autoconf automake libtool lighttpd -y

basedir=`pwd`

git clone https://github.com/FastCGI-Archives/fcgi2
cd fcgi2/
./autogen.sh
./configure
make
sudo make install
cd $basedir

mkdir -p build && cd build
cmake ..
make
sudo make install
cd ..
