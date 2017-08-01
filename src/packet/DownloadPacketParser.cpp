/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#include "DownloadPacketParser.h"
#include "base/Log.h"
#include "base/Error.h"
#include "base/Protocol.h"

/*!
 * Constructor
 */
DownloadPacketParser::DownloadPacketParser()
{
    //Constructor
}

/*!
 * Destructor
 */
DownloadPacketParser::~DownloadPacketParser()
{
    //Destructor
}

/*!
 *
 * Parse DOWNLOAD_INIT_REQ Packet
 * @param packet - packet to be parsed
 * @return
 *      SMB_SUCCESS - Successful
 *      SMB_ERROR - Failed
 */
int DownloadPacketParser::parse_download_req_init(Packet *packet)
{
    DEBUG_LOG("DownloadPacketParser::parse_download_req_init");
    assert(packet->_pb_msg != NULL);
    parse_credentials(packet);
    return SMB_SUCCESS;
}

/*!
 * Parse DOWNLOAD_INIT_RESP packet
 * @param packet
 * @return
 *      SMB_SUCCESS - Successful
 *      SMB_ERROR - Failed
 */
int DownloadPacketParser::parse_download_req_init_resp(Packet *packet)
{
    DEBUG_LOG("DownloadPacketParser::parse_download_req_init_resp");
    assert(packet->_pb_msg != NULL);
    packet->Dump();

    DownloadProcessor *_processor = dynamic_cast<DownloadProcessor *>(RequestProcessor::GetInstance());
    if (IS_NULL(_processor))
    {
        DEBUG_LOG("DownloadPacketParser::parse_download_req_init_resp invalid RequestProcessor");
        return SMB_ERROR;
    }

    //Initialise variables for DownloadProcessor
    _processor->SetSize(packet->_pb_msg->responsepacket().downloadinitresponse().fileinformation().size());
    _processor->SetCreateTime(packet->_pb_msg->responsepacket().downloadinitresponse().fileinformation().createtime());
    _processor->SetModifiedTime(
        packet->_pb_msg->responsepacket().downloadinitresponse().fileinformation().modifiedtime());
    _processor->SetEndOffset(packet->_pb_msg->responsepacket().downloadinitresponse().fileinformation().size());

    DEBUG_LOG("DownloadPacketParser::parse_download_req_init_resp size %d c_time %ld m_time %ld", _processor->Size(),
              _processor->CreateTime(), _processor->ModifiedTime());

    return SMB_SUCCESS;
}

/*!
 *
 * Parse DOWNLOAD_DATA_REQ Packet
 * @param data - buffer to be filled (ownership is transferred to caller)
 *
 * @return
 *      SMB_SUCCESS - Successful
 *      SMB_ERROR - Failed
 */
int DownloadPacketParser::parse_download_req_data(Packet *packet)
{
    DEBUG_LOG("DownloadPacketParser::parse_download_req_data");
    assert(packet->_pb_msg != NULL);
    packet->Dump();

    DownloadProcessor *_processor = dynamic_cast<DownloadProcessor *>(RequestProcessor::GetInstance());
    if (IS_NULL(_processor))
    {
        DEBUG_LOG("DownloadPacketParser::parse_download_req_data invalid RequestProcessor");
        return SMB_ERROR;
    }

    _processor->SetStartOffset(packet->_pb_msg->requestpacket().rangedownloadrequest().start());
    _processor->SetEndOffset(packet->_pb_msg->requestpacket().rangedownloadrequest().end());
    _processor->SetChunkSize(packet->_pb_msg->requestpacket().rangedownloadrequest().chunksize());

    return SMB_SUCCESS;
}

/*!
 * Parse DOWNLOAD_DATA_RESP packet
 * @param packet - packet to be parsed
 * @return
 *      SMB_SUCCESS - Successful
 *      SMB_ERROR - Failed
 */
int DownloadPacketParser::parse_download_resp_data(Packet *packet)
{
    DEBUG_LOG("DownloadPacketParser::parse_download_resp_data");
    packet->Dump();
    return SMB_SUCCESS;
}

/*!
 * Parse DOWNLOAD_END_RESP packet
 * @param packet - request packet to be parsed
 * @return
 *      SMB_SUCCESS - Successful
 *      SMB_ERROR - Failed
 */
int DownloadPacketParser::parse_download_resp_end(Packet *packet)
{
    DEBUG_LOG("DownloadPacketParser::parse_download_resp_end");
    packet->Dump();
    return SMB_SUCCESS;
}

/*!
 * Parse DOWNLOAD_ERROR packet
 * @param packet - request packet to be parsed
 * @return
 *      SMB_SUCCESS - Successful
 *      SMB_ERROR - Failed
 */
int DownloadPacketParser::parse_download_resp_error(Packet *packet)
{
    DEBUG_LOG("DownloadPacketParser::parse_download_resp_error");
    return parse_status(packet->_pb_msg->status());
}

/*!
 * parse credentials
 * @param packet
 * @return
 *      SMB_SUCCESS - Successful
 *      SMB_ERROR - Failed
 */
int DownloadPacketParser::parse_credentials(Packet *packet)
{
    DEBUG_LOG("DownloadPacketParser::parse_credentials");
    return IPacketParser::parse_credentials(packet);
}

/*!
 * parse status/error message
 * @param status
 * @return
 *      SMB_SUCCESS - Successful
 *      SMB_ERROR - Failed
 */
int DownloadPacketParser::parse_status(const Status &status)
{
    DEBUG_LOG("DownloadPacketParser::parse_status");
    return IPacketParser::parse_status(status);
}

/*!
 * Verify request-id
 * @param packet
 * @return
 *      SMB_SUCCESS - Successful
 *      SMB_ERROR - Failed
 */
int DownloadPacketParser::verify_request_id(Packet *packet)
{
    return IPacketParser::verify_request_id(packet);
}

/*!
 * Parse packet for Download module
 * @param packet - request packet
 * @return
 *      SMB_SUCCESS - Successful
 *      SMB_ERROR - Failed
 */
int DownloadPacketParser::ParsePacket(Packet *packet)
{
    DEBUG_LOG("DownloadPacketParser::ParsePacket");
    assert(packet);
    int ret;

    if (verify_request_id(packet) != SMB_SUCCESS)
    {
        return SMB_ERROR;
    }

    switch (packet->GetCMD())
    {
        case DOWNLOAD_INIT_REQ:
            ret = parse_download_req_init(packet);
            break;
        case DOWNLOAD_INIT_RESP:
            ret = parse_download_req_init_resp(packet);
            break;
        case DOWNLOAD_DATA_REQ:
            ret = parse_download_req_data(packet);
            break;
        case DOWNLOAD_DATA_RESP:
            ret = parse_download_resp_data(packet);
            break;
        case DOWNLOAD_END_RESP:
            ret = parse_download_resp_end(packet);
            break;
        case DOWNLOAD_ERROR:
            ret = parse_download_resp_error(packet);
            break;
        default:
            ret = SMB_ERROR;
            ERROR_LOG("Invalid Command type");
    }
    return ret;
}