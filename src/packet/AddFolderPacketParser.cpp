/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */
#include "base/Log.h"
#include "base/Error.h"
#include "base/Protocol.h"
#include "AddFolderPacketParser.h"

/*!
 * Constructor
 */
AddFolderPacketParser::AddFolderPacketParser()
{
    //Empty Constructor
}

/*!
 * Destructor
 */
AddFolderPacketParser::~AddFolderPacketParser()
{
    //Empty Destructor
}

/*!
 * Parse ADD_FOLDER_INIT_REQ packet
 * @param packet - request packet to be parsed
 * @return
 *      SMB_SUCCESS - Successful
 *      SMB_ERROR - Failed
 */
int AddFolderPacketParser::parse_add_folder_req(Packet *packet)
{
    DEBUG_LOG("AddFolderPacketParser::parse_add_folder_req");
    assert(packet->_data != NULL);
    packet->Dump();
    parse_credentials(packet);
    return SMB_SUCCESS;
}

/*!
 * Parse ADD_FOLDER_INIT_RESP packet
 * @param packet - request packet
 * @return
 *      SMB_SUCCESS - Successful
 *      SMB_ERROR - Failed
 */
int AddFolderPacketParser::parse_add_folder_resp(Packet *packet)
{
    DEBUG_LOG("AddFolderPacketParser::parse_add_folder_resp");
    assert(packet->_pb_msg != NULL);
    packet->Dump();
    DEBUG_LOG("AddFolderPacketParser::parse_add_folder_resp CreateTime %ld, ModifiedTime %ld",
              packet->_pb_msg->responsepacket().addfolderresponse().fileinformation().createtime(),
              packet->_pb_msg->responsepacket().addfolderresponse().fileinformation().modifiedtime());
    return SMB_SUCCESS;
}

/*!
 * Parse ADD_FOLDER_ERROR_RESP
 * @param packet - request packet
 * @return
 *      SMB_SUCCESS - Successful
 *      SMB_ERROR - Failed
 */
int AddFolderPacketParser::parse_add_folder_error(Packet *packet)
{
    DEBUG_LOG("AddFolderPacketParser::parse_add_folder_error");
    parse_status(packet->_pb_msg->status());
    return SMB_SUCCESS;
}

/*!
 * Parse error/status messages
 * @param status - Status msg to be parsed
 * @return
 * SMB_SUCCESS
 * Otherwise failure
 */
int AddFolderPacketParser::parse_status(const Status &status)
{
    DEBUG_LOG("AddFolderPacketParser::parse_status");
    IPacketParser::parse_status(status);
    return SMB_SUCCESS;
}

/*!
 * Parse Credentials
 * @param packet - packet to be parsed
 * @return
 * SMB_SUCCESS
 * Otherwise failure
 */
int AddFolderPacketParser::parse_credentials(Packet *packet)
{
    DEBUG_LOG("AddFolderPacketParser::parse_credentials");
    return IPacketParser::parse_credentials(packet);
}

/*!
 * Verify Request-ID
 * @param packet
 * @return
 * SMB_SUCCESS - successful
 * Otherwise - Failure
 */
int AddFolderPacketParser::verify_request_id(Packet *packet)
{
    return IPacketParser::verify_request_id(packet);
}

/*!
 * Parses packet received for Add-Folder request
 * @param packet - incoming packet
 * @return
 * SMB_SUCCESS - successful
 * Otherwise - Failure
 */
int AddFolderPacketParser::ParsePacket(Packet *packet)
{
    DEBUG_LOG("AddFolderPacketParser::ParsePacket");
    assert(packet);
    int ret;

    if (verify_request_id(packet) != SMB_SUCCESS)
    {
        return SMB_ERROR;
    }

    switch (packet->GetCMD())
    {
        case ADD_FOLDER_INIT_REQ:
            ret = parse_add_folder_req(packet);
            break;
        case ADD_FOLDER_INIT_RESP:
            ret = parse_add_folder_resp(packet);
            break;
        case ADD_FOLDER_ERROR_RESP:
            ret = parse_add_folder_error(packet);
            break;
        default:
            ret = SMB_ERROR;
            ERROR_LOG("Invalid Command type");
    }
    return ret;
}