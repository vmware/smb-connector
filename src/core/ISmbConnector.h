/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#ifndef I_SMBCONNECTOR_H_
#define I_SMBCONNECTOR_H_

#include "socket/UnixDomainSocket.h"

class SessionManager;

class ISmbConnector
{
public:
    virtual ~ISmbConnector(){};
    virtual int Init(const char *path, int op_code=0) = 0;
    virtual void Runloop() = 0;
    virtual int CleanUp() = 0;
    virtual int Quit() = 0;
    virtual UnixDomainSocket *GetSocket() = 0;
    virtual void ResetTimer() = 0;

#ifdef _DEBUG_
    virtual SessionManager *GetSessionManager() = 0;
#endif
};

#endif //I_SMBCONNECTOR_H_
