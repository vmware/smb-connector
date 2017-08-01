/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#ifndef DELETE_PACKET_CREATOR_H_
#define DELETE_PACKET_CREATOR_H_

#include "IPacketCreator.h"
#include "processor/DeleteProcessor.h"

class DeletePacketCreator: public IPacketCreator
{
private:
    int create_delete_req(Packet *packet);
    int create_delete_resp(Packet *packet, packet_data *data);

public:
    explicit DeletePacketCreator();
    virtual ~DeletePacketCreator();
    int CreatePacket(Packet *packet, int op_code, void *data);

};


#endif //DELETE_PACKET_CREATOR_H_
