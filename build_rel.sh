#!/bin/sh
rm -rf lib_rel
rm -rf lib
echo "Performing release build"

build_samba=1

if [ "$#" = 1 ]; then
	echo "samba build parameter supplied"
	build_samba=$1
fi

if [ ${build_samba} = 1 ]; then
	echo "building samba as well"
	mkdir lib_rel
	./build_samba_rel.sh
else
    if [ -f lib_rel.tar ]; then
	    echo "we already have pre-build libraries from samba as lib_rel.tar"
	    tar -xvhf lib_rel.tar
	 else
	    echo "lib_rel.tar not found"
	    echo "build failed"
	    exit
	fi
fi

##smbconnector
mv lib_rel lib
mkdir -p cmake-build-release/lib
cp -P lib/lib/private/* cmake-build-release/lib
cd cmake-build-release/lib
ln -s libsmbclient.so.0.2.3 libsmbclient.so
cd ../..
./del_unused_lib.sh cmake-build-release/lib
./generate_proto_buf.sh
./cmake_rel.sh

