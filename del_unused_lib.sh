#!/bin/sh
cd $1
echo "Deleting unused library..."
########## delete unused libraries #############

rm -rf libads-samba4.so libauth4-samba4.so libauth-samba4.so \
libauth-unix-token-samba4.so libcli-ldap-samba4.so libcli-spoolss-samba4.so \
libcluster-samba4.so libcmdline-credentials-samba4.so libdb-glue-samba4.so \
libdcerpc-samba4.so libdcerpc-samr.so.0 libdcerpc-samr.so.0.0.1 libdcerpc-server.so.0 \
libdcerpc-server.so.0.0.1 libdcerpc.so.0 libdcerpc.so.0.0.1 libdfs-server-ad-samba4.so \
libdlz-bind9-for-torture-samba4.so libdnsserver-common-samba4.so \
libdsdb-garbage-collect-tombstones-samba4.so libdsdb-module-samba4.so \
libevents-samba4.so libgpo-samba4.so libHDB-SAMBA4-samba4.so libhdb-samba4.so.11 \
libhdb-samba4.so.11.0.2 libheimntlm-samba4.so.1 libheimntlm-samba4.so.1.0.1 \
libhttp-samba4.so libidmap-samba4.so libkdc-samba4.so.2 libkdc-samba4.so.2.0.0 \
libldb-cmdline-samba4.so libLIBWBCLIENT-OLD-samba4.so \
libMESSAGING-samba4.so libndr-samba4.so libnetapi.so.0 libnetif-samba4.so \
libnet-keytab-samba4.so libnon-posix-acls-samba4.so libnpa-tstream-samba4.so \
libnss-info-samba4.so libnss-winbind.so.2 libnss-wins.so.2 libpac-samba4.so \
libpopt-samba3-samba4.so libpopt-samba4.so libposix-eadb-samba4.so \
libprinting-migrate-samba4.so libprocess-model-samba4.so libpyldb-util.so.1 \
libpyldb-util.so.1.1.29 libpytalloc-util.so.2 libpytalloc-util.so.2.1.9 \
libregistry-samba4.so libsamba-net-samba4.so libsamba-passdb.so.0 \
libsamba-passdb.so.0.26.0 libsamba-policy.so.0 libsamba-policy.so.0.0.1 \
libsamba-python-samba4.so libservice-samba4.so libshares-samba4.so \
libsmbclient-raw-samba4.so libsmbd-base-samba4.so libsmbd-conn-samba4.so \
libsmbldaphelper-samba4.so libsmbldap.so.0 libsmbpasswdparser-samba4.so \
libtorture-samba4.so libtrusts-util-samba4.so \
libxattr-tdb-samba4.so winbind_krb5_locator.so

################################################

