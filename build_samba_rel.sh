#!/bin/sh
echo "Perforing release build for samba..."
cd samba
./configure -j 4 --with-configdir=/opt/vmware/content-gateway/smb-connector --private-libraries=ALL --with-shared-modules=ALL --prefix=../lib_rel/ --without-gettext --without-systemd --without-ad-dc --without-pam --without-acl-support  --without-json --without-libarchive --without-ldap --without-ads --with-shared-modules=!vfs_snapper
make -j 4 && make -j 4 install
