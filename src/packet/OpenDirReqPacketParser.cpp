/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#include "OpenDirReqPacketParser.h"
#include "base/Log.h"
#include "base/Error.h"
#include "base/Protocol.h"

/*!
 * Constructor
 */
OpenDirPacketParser::OpenDirPacketParser()
{
    //Empty Constructor
}

/*!
 * Destructor
 */
OpenDirPacketParser::~OpenDirPacketParser()
{
    //Empty Destructor
}

/*!
 *
 * Parse GET_STRUCTURE_INIT_REQ Packet
 * @param packet - packet to be parsed
 *
 * @return
 *      SMB_SUCCESS - Successful
 *      SMB_ERROR - Failed
 */
int OpenDirPacketParser::parse_get_structure_req(Packet *packet)
{
    DEBUG_LOG("OpenDirPacketParser::parse_get_structure_req");
    assert(packet->_pb_msg != NULL);
    packet->Dump();
    parse_credentials(packet);

    if(packet->_pb_msg->requestpacket().folderstructurerequest().pagesize() <= 0)
    {
        DEBUG_LOG("OpenDirPacketParser::parse_get_structure_req page-size <=0");
        return SMB_ERROR;
    }

    OpenDirReqProcessor *_processor = dynamic_cast<OpenDirReqProcessor *>(RequestProcessor::GetInstance());
    if (IS_NULL(_processor))
    {
        DEBUG_LOG("OpenDirPacketParser::parse_get_structure_req invalid RequestProcessor");
        return SMB_ERROR;
    }

    _processor->SetShowOnlyFolders(packet->_pb_msg->requestpacket().folderstructurerequest().showonlyfolders());
    _processor->SetShowHiddenFiles(packet->_pb_msg->requestpacket().folderstructurerequest().showhiddenfiles());
    _processor->SetPageSize(packet->_pb_msg->requestpacket().folderstructurerequest().pagesize());

    /* if the url has '/'
     * the we need to fetch the details about the file or folder
     * otherwise its just the server url and we need to list down the shares
     */
    if (_processor->Url().find('/') == std::string::npos)
    {
        _processor->SetFetchShare(true);
    }
    return SMB_SUCCESS;

}

/*!
 * Parse GET_STRUCTURE_INIT_RESP packet
 * @param packet - packet to be parsed
 * @return
 *      SMB_SUCCESS - Successful
 *      SMB_ERROR - Failed
 */
int OpenDirPacketParser::parse_get_structure_resp(Packet *packet)
{
    DEBUG_LOG("OpenDirPacketParser::parse_get_structure_resp");
    assert(packet->_pb_msg);
    packet->Dump();
    int len = packet->_pb_msg->responsepacket().folderstructureresponse().fileinformation_size();
    for (int i = 0; i < len; ++i)
    {
        const FileInformation &f_info = packet->_pb_msg->responsepacket().folderstructureresponse().fileinformation(i);
        INFO_LOG("\t%s %ld %ld %ld %d", f_info.name().c_str(), f_info.size(), f_info.createtime(),
                 f_info.modifiedtime(), f_info.resourcetype());
    }
    return SMB_SUCCESS;
}

/*!
 * Parse GET_STRUCTURE_END_RESP packet
 * @param packet - packet to be parsed
 * @return
 *      SMB_SUCCESS - Successful
 *      SMB_ERROR - Failed
 */
int OpenDirPacketParser::parse_get_structure_resp_end(Packet *packet)
{
    DEBUG_LOG("OpenDirPacketParser::parse_get_structure_resp_end");
    packet->Dump();
    return SMB_SUCCESS;
}

/*!
 * Parse GET_STRUCTURE_ERROR_RESP packet
 * @param packet - request packet
 * @return
 *      SMB_SUCCESS - Successful
 *      SMB_ERROR - Failed
 */
int OpenDirPacketParser::parse_get_structure_error(Packet *packet)
{
    DEBUG_LOG("OpenDirPacketParser::parse_get_structure_error");
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
int OpenDirPacketParser::parse_credentials(Packet *packet)
{
    DEBUG_LOG("OpenDirPacketParser::parse_credentials");
    return IPacketParser::parse_credentials(packet);
}

/*!
 * Parse error/status msg
 * @param status
 * @return
 *      SMB_SUCCESS - Successful
 *      SMB_ERROR - Failed
 */
int OpenDirPacketParser::parse_status(const Status &status)
{
    DEBUG_LOG("OpenDirPacketParser::parse_status");
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
int OpenDirPacketParser::verify_request_id(Packet *packet)
{
    return IPacketParser::verify_request_id(packet);
}

/*!
 * Parse incoming packets for list-dir module
 * @param packet - request packet
 * @return
 *      SMB_SUCCESS - Successful
 *      SMB_ERROR - Failed
 */
int OpenDirPacketParser::ParsePacket(Packet *packet)
{
    DEBUG_LOG("OpenDirPacketParser::ParsePacket");
    assert(packet);
    int ret;

    if (verify_request_id(packet) != SMB_SUCCESS)
    {
        return SMB_ERROR;
    }

    switch (packet->GetCMD())
    {
        case GET_STRUCTURE_INIT_REQ:
            ret = parse_get_structure_req(packet);
            break;
        case GET_STRUCTURE_INIT_RESP:
            ret = parse_get_structure_resp(packet);
            break;
        case GET_STRUCTURE_END_RESP:
            ret = parse_get_structure_resp_end(packet);
            break;
        case GET_STRUCTURE_ERROR_RESP:
            ret = parse_get_structure_error(packet);
            break;
        default:
            ret = SMB_ERROR;
            ERROR_LOG("Invalid Command type");
    }
    return ret;
}