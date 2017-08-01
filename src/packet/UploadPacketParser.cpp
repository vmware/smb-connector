/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#include "UploadPacketParser.h"
#include "base/Error.h"
#include "base/Log.h"
#include "base/Protocol.h"

/*!
 * Constructor
 */
UploadPacketParser::UploadPacketParser()
{
    //Empty Constructor
}

/*!
 * Destructor
 */
UploadPacketParser::~UploadPacketParser()
{
    //Empty Destructor
}

/*!
 * Parse DOWNLOAD_UPLOAD_REQ_INIT packet
 * @param packet- request packet
 * @return
 *      SMB_SUCCESS - Successful
 *      SMB_ERROR - Failed
 */
int UploadPacketParser::parse_upload_req_init(Packet *packet)
{
    DEBUG_LOG("UploadPacketParser::parse_upload_req_init");
    assert(packet->_pb_msg != NULL);
    packet->Dump();
    parse_credentials(packet);
    return SMB_SUCCESS;
}

/*!
 * Parse UPLOAD_REQ_INIT_RESP packet
 * @param packet - request packet to be parsed
 * @return
 *      SMB_SUCCESS - Successful
 *      SMB_ERROR - Failed
 */
int UploadPacketParser::parse_upload_req_init_resp(Packet *packet)
{
    DEBUG_LOG("UploadPacketParser::parse_upload_req_init_resp");
    assert(packet->_pb_msg != NULL);
    packet->Dump();
    parse_status(packet->_pb_msg->status());
    return SMB_SUCCESS;
}

/*!
 * Parse UPLOAD_REQ_DATA packet
 * @param packet - request packet to be parsed
 * @return
 *      SMB_SUCCESS - Successful
 *      SMB_ERROR - Failed
 */
int UploadPacketParser::parse_upload_req_data(Packet *packet)
{
    DEBUG_LOG("UploadPacketParser::parse_upload_req_data");
    assert(packet->_data != NULL);
    packet->Dump();
    return SMB_SUCCESS;
}

/*!
 * Parse UPLOAD_REQ_DATA_ERROR
 * @param packet - request packet to be parsed
 * @return
 *      SMB_SUCCESS - Successful
 *      SMB_ERROR - Failed
 */
int UploadPacketParser::parse_upload_req_data_error(Packet *packet)
{
    DEBUG_LOG("UploadPacketParser::parse_upload_req_data_error");
    assert(packet->_pb_msg != NULL);
    packet->Dump();
    parse_status(packet->_pb_msg->status());
    return SMB_SUCCESS;
}

/*!
 * Parse UPLOAD_REQ_DATA_END packet
 * @param packet - request packet to be parsed
 * @return
 *      SMB_SUCCESS - Successful
 *      SMB_ERROR - Failed
 */
int UploadPacketParser::parse_upload_req_data_end(Packet *packet)
{
    DEBUG_LOG("UploadPacketParser::parse_upload_req_data_end");
    packet->Dump();
    return SMB_SUCCESS;
}

/*!
 * Parse UPLOAD_REQ_DATA_RESP
 * @param packet - request packet to be parsed
 * @return
 *      SMB_SUCCESS - Successful
 *      SMB_ERROR - Failed
 */
int UploadPacketParser::parse_upload_req_data_resp(Packet *packet)
{
    DEBUG_LOG("UploadPacketParser::parse_upload_req_data_resp");
    assert(packet->_pb_msg != NULL);
    packet->Dump();
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
int UploadPacketParser::parse_credentials(Packet *packet)
{
    DEBUG_LOG("UploadPacketParser::parse_credentials");
    return IPacketParser::parse_credentials(packet);
}

/*!
 * Parse status/error msg
 * @param status
 * @return
 *      SMB_SUCCESS - Successful
 *      SMB_ERROR - Failed
 */
int UploadPacketParser::parse_status(const Status &status)
{
    DEBUG_LOG("UploadPacketParser::parse_status");
    IPacketParser::parse_status(status);
    return SMB_SUCCESS;
}

/*!
 * Verify request id
 * @param packet
 * @return
 *      SMB_SUCCESS - Successful
 *      SMB_ERROR - Failed
 */
int UploadPacketParser::verify_request_id(Packet *packet)
{
    return IPacketParser::verify_request_id(packet);
}

int UploadPacketParser::ParsePacket(Packet *packet)
{
    DEBUG_LOG("UploadPacketParser::ParsePacket");
    assert(packet);
    int ret = SMB_ERROR;

    if (verify_request_id(packet) != SMB_SUCCESS)
    {
        return SMB_ERROR;
    }

    switch (packet->GetCMD())
    {
        case UPLOAD_INIT_REQ:
            ret = parse_upload_req_init(packet);
            break;
        case UPLOAD_INIT_RESP:
            ret = parse_upload_req_init_resp(packet);
            break;
        case UPLOAD_DATA_REQ:
            ret = parse_upload_req_data(packet);
            break;
        case UPLOAD_ERROR:
            ret = parse_upload_req_data_error(packet);
            break;
        case UPLOAD_END_REQ:
            ret = parse_upload_req_data_end(packet);
            break;
        case UPLOAD_END_RESP:
            ret = parse_upload_req_data_resp(packet);
            break;
        default:
            ret = SMB_ERROR;
            ERROR_LOG("Invalid Command type");
    }
    return ret;
}