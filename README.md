
SMB-Connector - C++ connector implementation around libsmbclient
=============================================

Overview
---------

SMB-Connector is a c++ connector around libsmbclient (samba.org).
It uses google's protocol buffers message for communication.

Supported OS Versions
----------------------
RHEL 7, SLES12-SP2


Dependencies
---------------------
gnutls, libprotobuf, log4cpp, google-test (gtest), doxygen (optional, required to generate documentation)

The directory structure is
```
|-src
    |- samba               - samba library [https://github.com/samba-team/samba]
    |- src
        |- base             - Logging, Error implementation
        |- packet           - Packet, Packet Creator, Packet Parser implementation
        |- protobuf         - protocol buffer files
        |- protocol_buffers - auto-generated files using protocol buffers (should be removed from code base)
        |- processor        - Processor implementation which process Request
        |- smb              - c++ wrapper around libsmbclient apis
        |- socket           - IO implementation for Unix Domain Socket using epoll
        |- core             - Core classes implementation (SessionManager, Client and Server)
    |- unit-tests          - unit test code
```


Build Instructions
--------------------

The project uses 'cmake' to build SMBConnector and 'make' to build samba

Ensure above mentioned dependencies are installed.

1. build_all.sh             - Samba and SMB-Connector debug as well as release build
2. build_debug.sh           - Samba and SMB-Connector debug build
3. build_rel.sh             - Samba and SMB-Connector release build
4. build_samba_debug.sh     - Samba debug build
5. build_samba_rel.sh       - Samba release build
6. cmake_debug.sh           - SMB-Connector debug build
7. cmake_rel.sh             - SMB-Connector release build
8. generate_gcov.sh         - Generates *.gcov file in gcov_report folder
9. generate_proto_buf.sh    - Generates protobuf files from .proto files


Run Unit-tests
---------------------

SMB-Connector uses gtest (google testing framework) for executing unit-tests

A local samba server needs to be setup

Steps to setup a local Samba server for unit-test
    1. Install Samba (yum install samba)
    2. Add a 'test' user (useradd -m test)
    3. Set the password for the 'test', the password should be 'test' (passwd test)
    4. Add it as samba user (smbpasswd -a test)
    5. Allow samba through SELinux (sudo setsebool -P samba_export_all_rw on)
