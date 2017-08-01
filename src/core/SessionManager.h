/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#ifndef SESSIONMANAGER_H_
#define SESSIONMANAGER_H_

#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>

#include "ISmbConnector.h"
#include "packet/Packet.h"
#include "socket/UnixDomainSocket.h"

class SessionManager
{
private:
    unsigned int _buff_size;
    ISmbConnector *_smbConnector;
    UnixDomainSocket *_sock;
    std::deque<Packet *> _res_queue;
    std::deque<Packet *> _req_queue;
    std::mutex _req_queue_mtx;
    std::mutex _res_queue_mtx;
    std::mutex _write_mtx;
    std::thread *_processor_thread;
    bool _is_ready;
    std::mutex _reader_lock;
    std::condition_variable _reader_cond;

    int process_request();
    void signal_process_request();

public:
    SessionManager();
    ~SessionManager();

    int Init(ISmbConnector *smbConnector);
    bool IsReady();
    int InitProcessor(Packet *packet);
    int ProcessReadEvent();
    int ProcessWriteEvent();
    int CleanUp();
    int Quit();

    void PushResponse(Packet *req);
    void PushResponseAgain(Packet *req);
    Packet *PopResponse();
    bool IsResponseSpaceAvailable();
    void FreeAllResponse();

    void PushRequest(Packet *req);
    void PushRequestAgain(Packet *req);
    Packet *PopRequest();
    bool IsRequestSpaceAvailable();
    Packet *GetLastRequest();
    void FreeAllRequest();

    void ResetTimer();
};


#endif //SESSIONMANAGER_H_
