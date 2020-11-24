/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#ifndef REQUEST_PROCESSOR_H_
#define REQUEST_PROCESSOR_H_

#include <thread>
#include <mutex>
#include <condition_variable>

#include "smb/SmbClient.h"
#include "base/Common.h"
#include "base/Configuration.h"
#include "core/SessionManager.h"
#include "socket/Epoll.h"
#include "socket/UnixDomainSocket.h"

#include "packet/Packet.h"
#include "packet/IPacketParser.h"
#include "packet/IPacketCreator.h"


extern int should_exit;

class RequestProcessor
{
protected:
    RequestProcessor(RequestProcessor &instance);
    RequestProcessor &operator=(RequestProcessor &instance);
    RequestProcessor();

    std::string _request_id;
    std::string _user_name;
    std::string _password;
    std::string _url;
    std::string _work_group;

    SessionManager *_sessionManager;
    IPacketParser *_packet_parser;
    IPacketCreator *_packet_creator;

    std::thread *_async_operation;
    bool _should_exit;
    bool _kerberos;

    static RequestProcessor *_instance;

public:
    virtual ~RequestProcessor();
    static RequestProcessor *GetInstance();
    static void SetInstance(RequestProcessor *);

    virtual int Init(std::string &id) = 0;
    virtual int ProcessRequest(Packet *) = 0;

    virtual void SetSessionManager(SessionManager *instance){ _sessionManager = instance; }
    virtual void Quit();

    /*Getters and Setters */
    const std::string &UserName() const;
    void SetUserName(const std::string &user_name);
    const bool &Kerberos() const;
    void SetKerberos(const bool &krb);
    const std::string &Password() const;
    void SetPassword(const std::string &password);
    const std::string &Url() const;
    void SetUrl(const std::string &url);
    const std::string &WorkGroup() const;
    void SetWorkGroup(const std::string &work_group);
    const std::string &RequestId() const;
    void SetRequestId(const std::string &id);
    IPacketCreator *PacketCreator() const;
    IPacketParser *PacketParser() const;

};


#endif //REQUEST_PROCESSOR_H_
