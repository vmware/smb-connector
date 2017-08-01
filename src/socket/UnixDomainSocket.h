/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */


#ifndef UNIXDOMAINSOCKET_H_
#define UNIXDOMAINSOCKET_H_

#include <string>
#include <netinet/in.h>
#include <sys/un.h>

/*!
 * UnixTCPSocket maintains the data of an opened Unix TCP socket
 */

class UnixDomainSocket
{
private:
    int fd;
    struct sockaddr_un peer_addr;
    struct sockaddr_un local_addr;
    bool non_blocking;
    bool is_bound;
public:
    UnixDomainSocket();
    explicit UnixDomainSocket(const char *sun_path);
    virtual ~UnixDomainSocket();

    int Create();
    int Connect();
    int Connect(const char *sun_path);
    void SetNonBlocking(bool value);
    int Bind();
    void SetFD(int value) { fd = value; };
    int GetFD() { return fd; };
    int InitListening();
    int Accept(UnixDomainSocket *&unix_socket);
    int Read(char *buffer, int maxlen);
    int Send(const char *buffer, int len);
    int Peek(char *buffer, int maxlen);
    int Close();
};

#endif /* UNIXDOMAINSOCKET_H_ */
