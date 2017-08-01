/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#ifndef OPENDIR_PACKET_PARSER_H_
#define OPENDIR_PACKET_PARSER_H_

#include "IPacketParser.h"
#include "processor/OpenDirReqProcessor.h"

class OpenDirPacketParser: public IPacketParser
{
private:

    int parse_get_structure_req(Packet *packet);
    int parse_get_structure_resp(Packet *packet);
    int parse_get_structure_resp_end(Packet *packet);
    int parse_get_structure_error(Packet *packet);

    virtual int parse_credentials(Packet *packet);
    virtual int parse_status(const Status &status);
    virtual int verify_request_id(Packet *packet);

public:
    explicit OpenDirPacketParser();
    virtual ~OpenDirPacketParser();

    virtual int ParsePacket(Packet *packet);
};


#endif //OPENDIR_PACKET_PARSER_H_
