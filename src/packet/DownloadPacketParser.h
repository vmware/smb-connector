/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#ifndef DOWNLOAD_PACKET_PARSER_H_
#define DOWNLOAD_PACKET_PARSER_H_

#include "IPacketParser.h"
#include "processor/DownloadProcessor.h"

class DownloadPacketParser: public IPacketParser
{
private:

    int parse_download_req_init(Packet *packet);
    int parse_download_req_init_resp(Packet *packet);
    int parse_download_req_data(Packet *packet);
    int parse_download_resp_data(Packet *packet);
    int parse_download_resp_end(Packet *packet);
    int parse_download_resp_error(Packet *packet);

    virtual int parse_credentials(Packet *packet);
    virtual int parse_status(const Status &status);
    virtual int verify_request_id(Packet *packet);

public:
    explicit DownloadPacketParser();
    virtual ~DownloadPacketParser();
    virtual int ParsePacket(Packet *packet);
};


#endif //DOWNLOAD_PACKET_PARSER_H_
