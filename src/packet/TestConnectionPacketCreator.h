/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#ifndef TESTCONNECTION_PACKET_CREATOR_H_
#define TESTCONNECTION_PACKET_CREATOR_H_

#include "IPacketCreator.h"
#include "processor/TestConnection.h"

class TestConnectionPacketCreator: public IPacketCreator
{
private:
    int create_test_connection_req(Packet *packet);
    int create_test_connection_resp(Packet *packet);

public:
    explicit TestConnectionPacketCreator();
    virtual ~TestConnectionPacketCreator();
    int CreatePacket(Packet *packet, int op_code, void *data);
};


#endif //TESTCONNECTION_PACKET_CREATOR_H_
