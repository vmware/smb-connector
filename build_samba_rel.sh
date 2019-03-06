#!/bin/sh
echo "Perforing release build for samba..."
cd samba
./configure -j 4 --private-libraries=ALL --with-shared-modules=ALL --prefix=../lib_rel/ --without-gettext --without-systemd --without-ad-dc --without-pam --without-acl-support --without-json-audit --without-libarchive
make -j 4 && make -j 4 install
