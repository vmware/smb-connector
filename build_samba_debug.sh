#!/bin/sh
echo "Perforing debug build for samba..."
echo "execute 'make && make install' if this is not first build else it will perform a clean build"
cd samba
./configure  -j 4 --enable-debug --private-libraries=ALL --with-shared-modules=ALL --prefix=../lib_debug/ --without-pam --without-gettext --without-systemd --without-acl-support
make && make install
