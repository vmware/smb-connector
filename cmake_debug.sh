#!/bin/sh
if [ -d cmake-build-debug ]
then
	cd cmake-build-debug
        cmake3 -DCMAKE_BUILD_TYPE=Debug ..
        make all
else
        mkdir cmake-build-debug
        cd cmake-build-debug
        cmake3 ..
        make all
fi
tar -cvf smb-connector.tar smbconnector lib ../smb.conf ../smb-connector.conf
