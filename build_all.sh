#!/bin/sh

curl https://download.samba.org/pub/samba/stable/samba-4.13.2.tar.gz > samba.tar.gz
tar -xvf samba.tar.gz && mv samba-4.13.2 samba
./build_debug.sh 1
./build_rel.sh 1
