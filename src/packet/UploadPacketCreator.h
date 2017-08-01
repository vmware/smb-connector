/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#ifndef UPLOAD_PACKET_CREATOR_H_
#define UPLOAD_PACKET_CREATOR_H_

#include "IPacketCreator.h"
#include "processor/UploadProcessor.h"

class UploadPacketCreator: public IPacketCreator
{
private:
    int create_upload_req_init(Packet *packet);
    int create_upload_req_data(Packet *packet, packet_data *data);
    int create_upload_req_end(Packet *packet);

public:
    explicit UploadPacketCreator();
    virtual ~UploadPacketCreator();
    virtual int CreatePacket(Packet *packet, int op_code, void *data);
};


#endif //UPLOAD_PACKET_CREATOR_H_
