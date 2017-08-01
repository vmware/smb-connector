/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#ifndef ADDFOLDER_PROCESSOR_H_
#define ADDFOLDER_PROCESSOR_H_


#include "RequestProcessor.h"

class AddFolderProcessor: public RequestProcessor
{
private:
    int process_add_folder_req();
    int process_add_folder_req_resp();
    int process_add_folder_req_error();

public:
    AddFolderProcessor();
    virtual ~AddFolderProcessor();

    virtual int Init(std::string &request_id);
    virtual int ProcessRequest(Packet *packet);
    struct stat *GetStat();
};


#endif //ADDFOLDER_PROCESSOR_H_
