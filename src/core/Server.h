/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#ifndef SERVER_H_
#define SERVER_H_


#include <thread>

#include "ISmbConnector.h"
#include "SessionManager.h"
#include "socket/UnixDomainSocket.h"
#include "socket/Epoll.h"

class Server: public ISmbConnector
{
private:
    UnixDomainSocket *_listen_sock;
    UnixDomainSocket *_client_sock;
    Epoll _epoll;
    EVENT _event_list[MAX_SIGNALED_EVENT];
    SessionManager _sessionManager;
    struct timespec _start;
    struct timespec _end;
    bool timer_expired();
    std::mutex _cleanup_mtx;

public:
    Server();
    virtual ~Server();

    int Init(const char *path, int op_code = 0);
    void Runloop();
    int CleanUp();
    int Quit();
    void ResetTimer() { clock_gettime(CLOCK_REALTIME, &_start); }

    UnixDomainSocket *GetSocket() { return _client_sock; }

#ifdef _DEBUG_
    virtual SessionManager *GetSessionManager() { return &_sessionManager; }
#endif

};


#endif //SERVER_H_
