#!/bin/sh
if [ -d cmake-build-release ]
then
	cd cmake-build-release
        cmake3 -DCMAKE_BUILD_TYPE=Release ..
        make all
else
        mkdir cmake-build-release
        cd cmake-build-release
        cmake3 ..
        make all
fi

#with symbols
tar -cvf smb-connector.tar smbconnector lib ../smb.conf ../smb-connector.conf
mv smb-connector.tar smb-connector_with_symbol.tar

#without symbols

strip -s -R .comment -R .note -R .note.ABI-tag  smbconnector
strip -s -R .comment -R .note -R .note.ABI-tag  lib/*

tar -cvf smb-connector.tar smbconnector lib ../smb.conf ../smb-connector.conf