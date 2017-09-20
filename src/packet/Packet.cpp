/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */


#include "Packet.h"
#include "base/Error.h"
#include "base/Log.h"
#include "base/Protocol.h"

/*!
 * Constructor
 */
Packet::Packet() : _complete(false), _hdr_sent(false), _p_len(0), _data(NULL), _pb_msg(NULL)
{
    memset(_header, 0, HEADER_SIZE);
}

Packet::~Packet()
{
    FREE_ARR(_data);
    FREE(_pb_msg);
}

/*!
 * Payload length from header
 * @return
 * payload-len
 */
unsigned int Packet::GetLength()
{
    uint32_t len = 0;
    memcpy(&len, _header + LENGTH_OFFSET, LEN_SIZE);
    len = ntohl(len);
    return len;
}

/*!
 * Returns Packet type from header
 * @return
 */
int Packet::GetCMD()
{
    return _pb_msg->command().cmd();
}

/*!
 * Returns unique identifier
 * @return
 */
std::string Packet::GetID()
{
    return _pb_msg->command().requestid();
}

/*!
 * Insert id, command-code and payload-len in packet header
 * @param pid - id
 * @param packet_code - Command
 * @param payload_len - length of payload
 * @return
 * SMB_SUCCESS - successful
 * Otherwise - failure
 */
int Packet::PutHeader()
{
    int payload_len = _pb_msg->ByteSize();
    uint32_t n_len = htonl(payload_len);
    _header[0] = VERSION;
    memcpy(_header + LENGTH_OFFSET, &n_len, LEN_SIZE);
    memset(_header + LENGTH_OFFSET + LEN_SIZE, 0, RESERVED_BYTES);
    return SMB_SUCCESS;
}

/*!
 * Insert payload into packet
 * @param data - payload
 * @return
 * SMB_SUCCESS - successful
 * Otherwise - failure
 */
int Packet::PutData()
{
    _data = ALLOCATE_ARR(char, GetLength());
    if (!ALLOCATED(_data))
    {
        ERROR_LOG("Packet::PutData, memory allocation failed");
        return SMB_ERROR;
    }
    DEBUG_LOG("Message Length %ld", _pb_msg->SerializeAsString().length());
    memcpy(_data, _pb_msg->SerializeAsString().data(), _pb_msg->SerializeAsString().size());
    return SMB_SUCCESS;
}

/*!
 * Parse the data to construct protobuf objects
 * @return
 * SMB_SUCCESS - successful
 * Otherwise - failure
 */
int Packet::ParseProtoBuffer()
{
    _pb_msg = ALLOCATE(Message);
    if (!ALLOCATED(_pb_msg))
    {
        ERROR_LOG("Packet::ParseProtoBuffer allocation failed");
        return SMB_ALLOCATION_FAILED;
    }

    if (!_pb_msg->ParseFromArray(_data, GetLength()))
    {
        ERROR_LOG("Packet::ParseProtoBuffer Cannot parse Message");
        FREE(_pb_msg);
        _pb_msg = NULL;
        return SMB_ERROR;
    }
    else
    {
        DEBUG_LOG("Packet::ParseProtoBuffer Message parse success");
        return SMB_SUCCESS;
    }
}

/*!
 * Reset packet and clear all member variables
 * @return
 * SMB_SUCCESS - successful
 * Otherwise - failure
 */
int Packet::Reset()
{
    if (_data)
    {
        FREE_ARR(_data);
        _data = NULL;
    }
    if (_pb_msg)
    {
        FREE(_pb_msg);
        _pb_msg = NULL;
    }
    _p_len = 0;
    _complete = false;
    memset(_header, 0, HEADER_SIZE);

    return SMB_SUCCESS;
}

/*!
 * Dump packet in log if DEBUG_LOG enabled
 */
void Packet::Dump()
{
    DEBUG_LOG("Packet::Dump ID:%s CMD:%s, LEN:%d", GetID().c_str(), ProtocolCommand(GetCMD()), GetLength());
}
