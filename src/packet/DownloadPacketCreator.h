/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#ifndef DOWNLOAD_PACKET_CREATOR_H_
#define DOWNLOAD_PACKET_CREATOR_H_

#include "IPacketCreator.h"
#include "processor/DownloadProcessor.h"

class DownloadPacketCreator: public IPacketCreator
{
private:
    int create_download_req_init(Packet *packet);
    int create_download_req_init_resp(Packet *packet);
    int create_download_req_data(Packet *packet, packet_data *data);
    int create_download_resp_data(Packet *packet, packet_data *data);
    int create_download_resp_end(Packet *packet);

public:
    explicit DownloadPacketCreator();
    virtual ~DownloadPacketCreator();
    virtual int CreatePacket(Packet *packet, int op_code, void *data);
};


#endif //DOWNLOAD_PACKET_CREATOR_H_
