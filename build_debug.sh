#!/bin/sh
rm -rf lib_debug
rm -rf lib
echo "Perforing debug build..."

build_samba=1

if [ "$#" = 1 ]; then
	echo "samba build parameter supplied"
	build_samba=$1
fi

if [ ${build_samba} = 1 ]; then
	echo "building samba as well"
	mkdir lib_debug
	./build_samba_debug.sh
else
    if [ -f lib_debug.tar ]; then
	    echo "we already have pre-build libraries from samba as lib_debug.tar"
	    tar -xvhf lib_debug.tar
	else
	    echo "lib_debug.tar not found"
	    echo "build failed"
	    exit
	fi
fi

##smbconnector
mv lib_debug lib
mkdir -p cmake-build-debug/lib
cp -P lib/lib/private/* cmake-build-debug/lib
cd cmake-build-debug/lib
ln -s libsmbclient.so.0.4.0 libsmbclient.so
cd ../..
./del_unused_lib.sh cmake-build-debug/lib
./generate_proto_buf.sh
./cmake_debug.sh
