/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#ifndef PACKET_H_
#define PACKET_H_

#include "base/Common.h"
#include "base/Constants.h"
#include "protocol_buffers/common.pb.h"

struct Packet
{
    bool _complete;
    bool _hdr_sent;
    char _header[HEADER_SIZE];
    unsigned int _p_len; //received/sent payload-length
    char *_data;
    Message *_pb_msg;

    Packet();
    ~Packet();

    unsigned int GetLength();
    int GetCMD();
    std::string GetID();

    int PutHeader();
    int PutData();

    int ParseProtoBuffer();

    int Reset();
    void Dump();
};

#endif //PACKET_H_
