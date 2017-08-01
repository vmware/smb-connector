/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#ifndef IPARSER_H_
#define IPARSER_H_

#include "Packet.h"

class RequestProcessor;

class IPacketParser
{
protected:
    virtual int parse_credentials(Packet *packet) = 0;
    virtual int parse_status(const Status &status) = 0;
    virtual int verify_request_id(Packet *packet) = 0;

public:
    IPacketParser();
    virtual ~IPacketParser();
    virtual int ParsePacket(Packet *packet) = 0;
};


#endif //IPARSER_H_
