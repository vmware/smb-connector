/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#ifndef OPENDIR_PACKET_CREATOR_H_
#define OPENDIR_PACKET_CREATOR_H_

#include "IPacketCreator.h"
#include "processor/OpenDirReqProcessor.h"

class OpenDirPacketCreator: public IPacketCreator
{
private:
    int create_get_structure_req(Packet *packet);
    int create_get_structure_resp(Packet *packet);
    int create_get_structure_end(Packet *packet);

public:
    explicit OpenDirPacketCreator();
    virtual ~OpenDirPacketCreator();
    int CreatePacket(Packet *packet, int op_code, void *data);

};

#endif //OPENDIR_PACKET_CREATOR_H_
