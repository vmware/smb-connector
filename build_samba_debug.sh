#!/bin/sh
echo "Perforing debug build for samba..."
echo "execute 'make && make install' if this is not first build else it will perform a clean build"
cd samba
./configure  -j 4 --with-configdir=/opt/vmware/content-gateway/smb-connector --enable-debug --private-libraries=ALL --with-shared-modules=ALL --prefix=../lib_debug/ --without-pam --without-ad-dc --without-gettext --without-systemd --without-json --without-acl-support  --without-libarchive --without-ldap --without-ads --with-shared-modules=!vfs_snapper
make -j 4 && make -j 4 install
