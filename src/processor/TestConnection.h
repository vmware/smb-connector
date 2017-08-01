/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#ifndef TESTCONNECTION_PROCESSOR_H_
#define TESTCONNECTION_PROCESSOR_H_


#include "RequestProcessor.h"

class TestConnection: public RequestProcessor
{
private:
    int process_test_connection_req();
    int process_test_connection_req_resp();
    int process_test_connection_req_error();

public:
    TestConnection();
    virtual ~TestConnection();

    virtual int Init(std::string &request_id);
    virtual int ProcessRequest(Packet *packet);
    virtual void Quit();
    struct file_info *GetFileInfo();
    struct stat *GetStat();
};


#endif //TESTCONNECTION_PROCESSOR_H_
