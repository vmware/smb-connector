/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#ifndef DELETE_PACKET_PARSER_H_
#define DELETE_PACKET_PARSER_H_

#include "IPacketParser.h"
#include "processor/DeleteProcessor.h"

class DeletePacketParser: public IPacketParser
{
private:
    int parse_delete_req(Packet *packet);
    int parse_delete_resp(Packet *packet);
    int parse_delete_error(Packet *packet);

    virtual int parse_credentials(Packet *packet);
    virtual int parse_status(const Status &status);
    virtual int verify_request_id(Packet *packet);

public:
    explicit DeletePacketParser();
    virtual ~DeletePacketParser();
    virtual int ParsePacket(Packet *packet);

};


#endif //DELETE_PACKET_PARSER_H_
