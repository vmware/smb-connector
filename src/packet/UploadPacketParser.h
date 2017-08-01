/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#ifndef UPLOAD_PACKET_PARSER_H_
#define UPLOAD_PACKET_PARSER_H_

#include "IPacketParser.h"
#include "processor/UploadProcessor.h"

class UploadPacketParser: public IPacketParser
{
private:
    /* Upload file */
    int parse_upload_req_init(Packet *packet);
    int parse_upload_req_init_resp(Packet *packet);
    int parse_upload_req_data(Packet *packet);
    int parse_upload_req_data_error(Packet *packet);
    int parse_upload_req_data_end(Packet *packet);
    int parse_upload_req_data_resp(Packet *packet);

    virtual int parse_credentials(Packet *packet);
    virtual int parse_status(const Status &status);
    virtual int verify_request_id(Packet *packet);

public:
    explicit UploadPacketParser();
    virtual ~UploadPacketParser();
    virtual int ParsePacket(Packet *packet);
};

#endif //UPLOAD_PACKET_PARSER_H_
