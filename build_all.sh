#!/bin/sh

curl https://download.samba.org/pub/samba/stable/samba-4.9.4.tar.gz > samba.tar.gz
tar -xvf samba.tar.gz && mv samba-4.9.4 samba
./build_debug.sh 0
./build_rel.sh 0
