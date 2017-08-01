/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#ifndef CLIENT_H_
#define CLIENT_H_

#include <thread>
#include "base/Common.h"
#include "socket/UnixDomainSocket.h"
#include "socket/Epoll.h"

class Client: public ISmbConnector
{
private:
    UnixDomainSocket *_sock;
    Epoll _epoll;
    EVENT _event_list[MAX_SIGNALED_EVENT];
    std::string _sun_path;
    SessionManager _sessionManager;

public:
    Client();
    virtual ~Client();

    virtual int Init(const char *path, int op_code);
    virtual void Runloop();
    virtual int CleanUp();
    virtual int Quit();
    virtual UnixDomainSocket *GetSocket() { return _sock; }
    void ResetTimer(){}
#ifdef _DEBUG_
    virtual SessionManager *GetSessionManager(){ return &_sessionManager; }
#endif
};


#endif //CLIENT_H_