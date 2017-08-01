/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#ifndef ADDFOLDER_PACKET_PARSER_H_
#define ADDFOLDER_PACKET_PARSER_H_


#include "IPacketParser.h"
#include "processor/AddFolderProcessor.h"

class AddFolderPacketParser: public IPacketParser
{
private:

    int parse_add_folder_req(Packet *packet);
    int parse_add_folder_resp(Packet *packet);
    int parse_add_folder_error(Packet *packet);

    virtual int parse_credentials(Packet *packet);
    virtual int parse_status(const Status &status);
    virtual int verify_request_id(Packet *packet);

public:
    explicit AddFolderPacketParser();
    virtual ~AddFolderPacketParser();
    virtual int ParsePacket(Packet *packet);
};


#endif //ADDFOLDER_PACKET_PARSER_H_
