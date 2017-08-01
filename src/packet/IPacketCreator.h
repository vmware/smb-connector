/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#ifndef IPACKETCREATOR_H_
#define IPACKETCREATOR_H_

#include "base/Common.h"
#include "Packet.h"

struct packet_download_req_data
{
    off_t start;
    off_t end;
    size_t chunk_size;
};
struct packet_upload_download_data
{
    char *payload;
    int payload_len;
};

struct packet_delete_resp
{
    bool is_directory;
};

union packet_data
{
    packet_download_req_data dowload_req_data;
    packet_upload_download_data download_upload_data;
    packet_delete_resp delete_resp;
};

class IPacketCreator
{
public:
    IPacketCreator();
    virtual ~IPacketCreator();

    virtual int CreatePacket(Packet *packet, int op_code, void *data) = 0;
    int CreateCredentialPacket(Packet *packet);
    int CreateStatusPacket(Packet *packet, int cmd, int status_code, bool smbc_status = false);
};


#endif //IPACKETCREATOR_H_
