/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#ifndef ADDFOLDER_PACKET_CREATOR_H_
#define ADDFOLDER_PACKET_CREATOR_H_

#include "IPacketCreator.h"
#include "processor/AddFolderProcessor.h"

class AddFolderPacketCreator: public IPacketCreator
{
private:
    int create_add_folder_req(Packet *packet);
    int create_add_folder_resp(Packet *packet);

public:
    explicit AddFolderPacketCreator();
    virtual ~AddFolderPacketCreator();
    virtual int CreatePacket(Packet *packet, int op_code, void *data);
};


#endif //ADDFOLDER_PACKET_CREATOR_H_
