/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#include "base/Error.h"
#include "base/Protocol.h"
#include "base/Log.h"

#include "packet/TestConnectionPacketCreator.h"
#include "packet/TestConnectionPacketParser.h"
/*!
 * Constructor
 */
TestConnection::TestConnection()
{
    //Constructor
}

/*!
 * Destructor
 */
TestConnection::~TestConnection()
{
    //Destructor
}

/*!
 * Process TEST_CONNECTION_INIT_REQ packet
 * @return
 * SMB_SUCCESS    - Successful
 * Otherwise - Failed
 */
int TestConnection::process_test_connection_req()
{
    DEBUG_LOG("TestConnection::process_test_connection_req");
    SmbClient::GetInstance()->CredentialsInit(_url, _work_group, _user_name, _password);
    int ret = SmbClient::GetInstance()->OpenDir();
    if (ret != SMB_SUCCESS)
    {
        int err = errno;
        WARNING_LOG("TestConnection::process_test_connection_req open as directory error:%d", err);
        if (err == ENOTDIR)
        {
            INFO_LOG("TestConnection::process_test_connection_req trying to open as file now");
            ret = SmbClient::GetInstance()->OpenFile(O_RDONLY);
        }

        /* definitely an error */
        if (ret != SMB_SUCCESS)
        {
            ERROR_LOG("TestConnection::process_test_connection_req open failed");
            Packet *resp = ALLOCATE(Packet);
            _packet_creator->CreateStatusPacket(resp, TEST_CONNECTION_ERROR_RESP, err, true);
            _sessionManager->PushResponse(resp);
            _sessionManager->ProcessWriteEvent();
            return SMB_ERROR;
        }
    }

    Packet *resp = ALLOCATE(Packet);
    ret = _packet_creator->CreatePacket(resp, TEST_CONNECTION_INIT_RESP, NULL);
    if (ret != SMB_SUCCESS)
    {
        _packet_creator->CreateStatusPacket(resp, TEST_CONNECTION_ERROR_RESP, 0);
    }
    _sessionManager->PushResponse(resp);
    _sessionManager->ProcessWriteEvent();
    DEBUG_LOG("TestConnection::process_test_connection_req success");
    return ret;
}

/*!
 * Process TEST_CONNECTION_INIT_RESP packet
 * @return
 * SMB_SUCCESS    - Successful
 * Otherwise - Failed
 */
int TestConnection::process_test_connection_req_resp()
{
    DEBUG_LOG("TestConnection::process_test_connection_req_resp");
    Configuration &c = Configuration::GetInstance();
    if (!atoi(c[C_OP_MODE]))
    {
        should_exit = 1;
    }
    return SMB_SUCCESS;
}

/*!
 * Process TEST_CONNECTION_ERROR_RESP packet
 * @return
 * SMB_SUCCESS    - Successful
 * Otherwise - Failed
 */
int TestConnection::process_test_connection_req_error()
{
    DEBUG_LOG("TestConnection::process_test_connection_req_error");
    Configuration &c = Configuration::GetInstance();
    if (!atoi(c[C_OP_MODE]))
    {
        should_exit = 1;
    }
    return SMB_SUCCESS;
}

/*!
 * Initialisation
 * @param request_id - request id
 * @return
 * SMB_SUCCESS    - Successful
 * Otherwise - Failed
 */
int TestConnection::Init(std::string &request_id)
{
    DEBUG_LOG("TestConnection::Init");
    _packet_parser = new TestConnectionPacketParser();
    _packet_creator = new TestConnectionPacketCreator();
    RequestProcessor::Init(request_id);
    return SMB_SUCCESS;
}

/*!
 * Process packet for test-connection/list-share module
 * @param packet
 * @return
 * SMB_SUCCESS    - Successful
 * Otherwise - Failed
 */
int TestConnection::ProcessRequest(Packet *packet)
{
    DEBUG_LOG("TestConnection::ProcessRequest");
    assert(packet != NULL);
    assert(packet->_data != NULL);

    if (packet == NULL || packet->_data == NULL)
    {
        ERROR_LOG("TestConnection::ProcessRequest NULL packet");
        return SMB_ERROR;
    }

    int ret = _packet_parser->ParsePacket(packet);
    if (ret != SMB_SUCCESS)
    {
        ERROR_LOG("TestConnection::ProcessRequest, invalid packet");
        Packet *req = ALLOCATE(Packet);
        _packet_creator->CreateStatusPacket(req, TEST_CONNECTION_ERROR_RESP, ret);
        _sessionManager->PushResponse(req);
        _sessionManager->ProcessWriteEvent();
        return ret;
    }

    DEBUG_LOG("TestConnection::ProcessRequest Command %s", ProtocolCommand(packet->GetCMD()));
    switch (packet->GetCMD())
    {
        case TEST_CONNECTION_INIT_REQ:
            ret = process_test_connection_req();
            break;
        case TEST_CONNECTION_INIT_RESP:
            ret = process_test_connection_req_resp();
            break;
        case TEST_CONNECTION_ERROR_RESP:
            ret = process_test_connection_req_error();
            break;
        default:
            ERROR_LOG("Invalid cmd");
            ret = SMB_INVALID_PACKET;
            break;
    }

    return ret;
}

/*!
 * Cleanup
 */
void TestConnection::Quit()
{
    DEBUG_LOG("TestConnection::Quit");
    SmbClient::GetInstance()->CloseDir();
    RequestProcessor::Quit();
}

/*!
 * Get attributes for share
 * @return
 * file_info - Successful
 * NULL - Failed
 */
struct file_info *TestConnection::GetFileInfo()
{
    DEBUG_LOG("TestConnection::GetFileInfo");
    return SmbClient::GetInstance()->GetNextFileInfo();
}

/*!
 * Get the file stat
 * @return
 * stat - Successful
 */
struct stat *TestConnection::GetStat()
{
    return SmbClient::GetInstance()->FileStat();
}
