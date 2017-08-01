/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#ifndef DOWNLOAD_PROCESSOR_H_
#define DOWNLOAD_PROCESSOR_H_

#include <fstream>

#include "RequestProcessor.h"

class DownloadProcessor: public RequestProcessor
{
private:
    unsigned int _start_offset;
    unsigned int _end_offset;
    int _size;
    uint64_t _chunk_size;
    uint64_t _c_time;
    uint64_t _m_time;
    std::ofstream _file;

    int process_download_req_init();
    int process_download_req_init_resp();
    int process_download_req_data();
    int process_download_resp_data(Packet *packet);
    int process_download_resp_end();
    int process_download_resp_error();
    int download_file_async();

public:
    DownloadProcessor();
    virtual ~DownloadProcessor();

    virtual int Init(std::string &request_id);
    virtual int ProcessRequest(Packet *request);
    int OpenFile();
    struct stat *GetStat();
    void SetStartOffset(unsigned int _start_offset);
    void SetEndOffset(unsigned int _end_offset);
    int Size() const;
    void SetSize(int _size);
    const uint64_t &CreateTime() const;
    void SetCreateTime(const uint64_t &_c_time);
    const uint64_t &ModifiedTime() const;
    void SetModifiedTime(const uint64_t &_m_time);
    void SetChunkSize(uint64_t _chunk_size);
};


#endif //DOWNLOAD_PROCESSOR_H_
