/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#ifndef TESTCONNECTION_PACKET_PARSER_H_
#define TESTCONNECTION_PACKET_PARSER_H_

#include "IPacketParser.h"
#include "processor/TestConnection.h"

class TestConnectionPacketParser : public IPacketParser
{
private:
    int parse_test_connection_req(Packet *packet);
    int parse_test_connection_resp(Packet *packet);
    int parse_test_connection_error(Packet *packet);

    virtual int parse_credentials(Packet *packet);
    virtual int parse_status(const Status &status);
    virtual int verify_request_id(Packet *packet);

public:
    explicit TestConnectionPacketParser();
    ~TestConnectionPacketParser();
    virtual int ParsePacket(Packet *packet);
};


#endif //TESTCONNECTION_PACKET_PARSER_H_
