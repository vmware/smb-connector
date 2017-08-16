/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#include "DeletePacketParser.h"
#include "base/Log.h"
#include "Packet.h"
#include "base/Error.h"
#include "base/Protocol.h"

/*!
 * Constructor
 */
DeletePacketParser::DeletePacketParser()
{
    //Empty Constructor
}

/*!
 * Destructor
 */
DeletePacketParser::~DeletePacketParser()
{
    //Empty Destructor
}

/*!
 * Parse DELETE_INIT_REQ packet
 * @param packet
 * @return
 *      SMB_SUCCESS - Successful
 *      SMB_ERROR - Failed
 */
int DeletePacketParser::parse_delete_req(Packet *packet)
{
    DEBUG_LOG("DeletePacketParser::parse_delete_req");
    assert(packet->_data != NULL);
    packet->Dump();
    parse_credentials(packet);
    return SMB_SUCCESS;
}

/*!
 * Parse DELETE_INIT_RESP packet
 * @param packet - request packet to be parsed
 * @return
 *      SMB_SUCCESS - Successful
 *      SMB_ERROR - Failed
 */
int DeletePacketParser::parse_delete_resp(Packet *packet)
{
    DEBUG_LOG("DeletePacketParser::parse_delete_resp");
    assert(packet->_pb_msg != NULL);
    packet->Dump();
    INFO_LOG("DeletePacketParser::parse_delete_resp IsDirectory: %d",
              packet->_pb_msg->responsepacket().deleteresourceresponse().fileinformation().isdirectory());
    return SMB_SUCCESS;
}

/*!
 * Parse DELETE_ERROR_RESP
 * @param packet - packet to be parsed
 * @return
 *      SMB_SUCCESS - Successful
 *      SMB_ERROR - Failed
 */
int DeletePacketParser::parse_delete_error(Packet *packet)
{
    DEBUG_LOG("DeletePacketParser::parse_delete_error");
    parse_status(packet->_pb_msg->status());
    return SMB_SUCCESS;
}

/*!
 * Parse credentials
 * @param packet - request packet
 * @return
 *      SMB_SUCCESS - Successful
 *      SMB_ERROR - Failed
 */
int DeletePacketParser::parse_credentials(Packet *packet)
{
    DEBUG_LOG("DeletePacketParser::parse_credentials");
    return IPacketParser::parse_credentials(packet);
}

/*!
 * Parse error/status message
 * @param status
 * @return
 *      SMB_SUCCESS - Successful
 *      SMB_ERROR - Failed
 */
int DeletePacketParser::parse_status(const Status &status)
{
    DEBUG_LOG("DeletePacketParser::parse_status");
    IPacketParser::parse_status(status);
    return SMB_SUCCESS;
}

/*!
 * Verify Request-ID
 * @param packet
 * @return
 *      SMB_SUCCESS - Successful
 *      SMB_ERROR - Failed
 */
int DeletePacketParser::verify_request_id(Packet *packet)
{
    return IPacketParser::verify_request_id(packet);
}

/*!
 * Parse packet for delete module
 * @param packet - request packet
 * @return
 *      SMB_SUCCESS - Successful
 *      SMB_ERROR - Failed
 */
int DeletePacketParser::ParsePacket(Packet *packet)
{
    DEBUG_LOG("DeletePacketParser::ParsePacket");
    assert(packet);
    int ret;

    if (verify_request_id(packet) != SMB_SUCCESS)
    {
        return SMB_ERROR;
    }

    switch (packet->GetCMD())
    {
        case DELETE_INIT_REQ:
            ret = parse_delete_req(packet);
            break;
        case DELETE_INIT_RESP:
            ret = parse_delete_resp(packet);
            break;
        case DELETE_ERROR_RESP:
            ret = parse_delete_error(packet);
            break;
        default:
            ret = SMB_ERROR;
            ERROR_LOG("Invalid Command type");
    }
    return ret;
}
