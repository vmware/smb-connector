#!/bin/sh
echo "Perforing debug build for samba..."
echo "execute 'make && make install' if this is not first build else it will perform a clean build"
cd samba
./configure  -j 4 --enable-debug --private-libraries=ALL --with-shared-modules=ALL --prefix=../lib_debug/ --without-pam --without-ad-dc --without-gettext --without-systemd --without-acl-support --without-json-audit --without-libarchive
make -j 4 && make -j 4 install
