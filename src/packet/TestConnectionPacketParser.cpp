/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#include "TestConnectionPacketParser.h"
#include "base/Log.h"
#include "Packet.h"
#include "base/Error.h"
#include "base/Protocol.h"

/*!
 * Constructor
 */
TestConnectionPacketParser::TestConnectionPacketParser()
{
    //Constructor
}

/*!
 * Destructor
 */
TestConnectionPacketParser::~TestConnectionPacketParser()
{
    //Destructor
}

/*!
 * Parse List share request packet
 * @param packet
 * @return
 *      SMB_SUCCESS - Successful
 *      SMB_ERROR - Failed
 */
int TestConnectionPacketParser::parse_test_connection_req(Packet *packet)
{
    DEBUG_LOG("TestConnectionPacketParser::parse_test_connection_req");
    assert(packet->_data != NULL);
    packet->Dump();
    parse_credentials(packet);
    return SMB_SUCCESS;
}

/*!
 * Parse List share resp
 * @param packet
 * @return
 *      SMB_SUCCESS - Successful
 *      SMB_ERROR - Failed
 */
int TestConnectionPacketParser::parse_test_connection_resp(Packet *packet)
{
    DEBUG_LOG("TestConnectionPacketParser::parse_test_connection_resp");
    assert(packet->_pb_msg != NULL);
    packet->Dump();
    INFO_LOG("TestConnectionPacketParser::parse_test_connection_resp Name: %s IsDirectory: %d",
             packet->_pb_msg->responsepacket().testconnectionresponse().fileinformation().name().c_str(),
             packet->_pb_msg->responsepacket().testconnectionresponse().fileinformation().isdirectory());
    return SMB_SUCCESS;
}

/*!
 * Parse list-share error
 * @param packet
 * @return
 *      SMB_SUCCESS - Successful
 *      SMB_ERROR - Failed
 */
int TestConnectionPacketParser::parse_test_connection_error(Packet *packet)
{
    DEBUG_LOG("TestConnectionPacketParser::parse_test_connection_error");
    assert(packet->_pb_msg != NULL);
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
int TestConnectionPacketParser::parse_credentials(Packet *packet)
{
    DEBUG_LOG("TestConnectionPacketParser::parse_credentials");
    return IPacketParser::parse_credentials(packet);
}

/*!
 * Parse error/status msg for list share
 * @param status
 * @return
 *      SMB_SUCCESS - Successful
 *      SMB_ERROR - Failed
 */
int TestConnectionPacketParser::parse_status(const Status &status)
{
    DEBUG_LOG("TestConnectionPacketParser::parse_status");
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
int TestConnectionPacketParser::verify_request_id(Packet *packet)
{
    return IPacketParser::verify_request_id(packet);
}

/*!
 * Parse incoming packet for List Share module
 * @param packet - request packet
 * @return
 *      SMB_SUCCESS - Successful
 *      SMB_ERROR - Failed
 */
int TestConnectionPacketParser::ParsePacket(Packet *packet)
{
    DEBUG_LOG("TestConnectionPacketParser::ParsePacket");
    assert(packet);
    int ret;

    if (verify_request_id(packet) != SMB_SUCCESS)
    {
        return SMB_ERROR;
    }

    switch (packet->GetCMD())
    {
        case TEST_CONNECTION_INIT_REQ:
            ret = parse_test_connection_req(packet);
            break;
        case TEST_CONNECTION_INIT_RESP:
            ret = parse_test_connection_resp(packet);
            break;
        case TEST_CONNECTION_ERROR_RESP:
            ret = parse_test_connection_error(packet);
            break;
        default:
            ret = SMB_ERROR;
            ERROR_LOG("Invalid Command type");
    }
    return ret;
}