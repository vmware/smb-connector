/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#ifndef DELETE_PROCESSOR_H_
#define DELETE_PROCESSOR_H_


#include "RequestProcessor.h"

class DeleteProcessor: public RequestProcessor
{
private:
    int process_delete_req();
    int process_delete_req_resp();
    int process_delete_req_error();

public:
    DeleteProcessor();
    virtual ~DeleteProcessor();

    virtual int Init(std::string &request_id);
    int ProcessRequest(Packet *packet);
};

#endif //DELETE_PROCESSOR_H_
