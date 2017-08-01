/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#ifndef UPLOAD_PROCESSOR_H_
#define UPLOAD_PROCESSOR_H_

#include <fstream>

#include "processor/RequestProcessor.h"

class UploadProcessor: public RequestProcessor
{
private:
    std::ifstream _file;
    unsigned int _bytes_uploaded;
    bool _upload_success;

    int process_upload_req_init();
    int process_upload_req_init_resp();
    int process_upload_req_data(Packet *packet);
    int process_upload_req_data_error();
    int process_upload_req_data_end();
    int process_upload_req_data_resp();
    int upload_async();

public:
    UploadProcessor();
    virtual ~UploadProcessor();

    virtual int Init(std::string &request_id);
    virtual int ProcessRequest(Packet *request);
    virtual void Quit();
    void OpenFile();
};


#endif //UPLOAD_PROCESSOR_H_
