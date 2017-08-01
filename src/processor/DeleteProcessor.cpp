/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#include <future>

#include "base/Error.h"
#include "base/Log.h"
#include "base/Protocol.h"
#include "packet/DeletePacketParser.h"
#include "packet/DeletePacketCreator.h"

/*!
 * Constructor
 */
DeleteProcessor::DeleteProcessor()
{
    //Constructor
}

/*!
 * Destructor
 */
DeleteProcessor::~DeleteProcessor()
{
    //Destructor
}

/*!
 * Process delete file/folder request from client
 * @return
 * SMB_SUCCESS - Success
 * Otherwise - Failure
 */
int DeleteProcessor::process_delete_req()
{
    DEBUG_LOG("DeleteProcessor::process_delete_req");
    SmbClient::GetInstance()->CredentialsInit(_url, _work_group, _user_name, _password);
    bool isDirectory = false;
    int ret = SmbClient::GetInstance()->Delete(isDirectory);

    if (ret != SMB_SUCCESS)
    {
        DEBUG_LOG("DeleteProcessor::process_delete_req delete %s failed", _url.c_str());
        ret = errno;
        Packet *resp = ALLOCATE(Packet);
        _packet_creator->CreateStatusPacket(resp, DELETE_ERROR_RESP, ret, true);
        _sessionManager->PushResponse(resp);
        _sessionManager->ProcessWriteEvent();
        return SMB_ERROR;
    }

    Packet *resp = ALLOCATE(Packet);
    _packet_creator->CreatePacket(resp, DELETE_INIT_RESP, &isDirectory);
    _sessionManager->PushResponse(resp);
    _sessionManager->ProcessWriteEvent();

    DEBUG_LOG("DeleteProcessor::process_delete_req %s deleted", _url.c_str());

    return SMB_SUCCESS;
}

/*!
 * Process delete file/folder response
 * @return
 * SMB_SUCCESS - Success
 */
int DeleteProcessor::process_delete_req_resp()
{
    DEBUG_LOG("DeleteProcessor::process_delete_req_resp");
    Configuration &c = Configuration::GetInstance();
    if (!atoi(c[C_OP_MODE]))
    {
        should_exit = 1;
    }
    return SMB_SUCCESS;
}

/*!
 * Process error happened during delete file/folder
 * @return
 * SMB_SUCCESS - Success
 */
int DeleteProcessor::process_delete_req_error()
{
    DEBUG_LOG("DeleteProcessor::process_delete_req_error");
    Configuration &c = Configuration::GetInstance();
    if (!atoi(c[C_OP_MODE]))
    {
        should_exit = 1;
    }
    return SMB_SUCCESS;
}

/*!
 * Initialisation
 * @param request_id - request_id
 * @return
 * SMB_SUCCESS - Success
 * Otherwise - Failure
 */
int DeleteProcessor::Init(std::string &request_id)
{
    DEBUG_LOG("DeleteProcessor::Init");
    _packet_parser = new DeletePacketParser();
    _packet_creator = new DeletePacketCreator();
    return RequestProcessor::Init(request_id);
}

/*!
 * Process requests from Client
 * @param packet
 * @return
 * SMB_SUCCESS - Success
 * Otherwise - Failure
 */
int DeleteProcessor::ProcessRequest(Packet *packet)
{
    DEBUG_LOG("DeleteProcessor::ProcessRequest");

    assert(packet != NULL);
    assert(packet->_data != NULL);

    if (packet == NULL || packet->_data == NULL)
    {
        ERROR_LOG("DeleteProcessor::ProcessRequest NULL packet");
        return SMB_ERROR;
    }

    int ret = _packet_parser->ParsePacket(packet);
    if (ret != SMB_SUCCESS)
    {
        ERROR_LOG("DeleteProcessor::ProcessRequest malformed packet, send error");
        Packet *resp = ALLOCATE(Packet);
        _packet_creator->CreateStatusPacket(resp, DELETE_ERROR_RESP, ret);
        _sessionManager->PushResponse(resp);
        _sessionManager->ProcessWriteEvent();
        return ret;
    }

    DEBUG_LOG("DeleteProcessor::ProcessRequest Command %s", ProtocolCommand(packet->GetCMD()));
    switch (packet->GetCMD())
    {
        case DELETE_INIT_REQ:
            ret = process_delete_req();
            break;
        case DELETE_INIT_RESP:
            ret = process_delete_req_resp();
            break;
        case DELETE_ERROR_RESP:
            ret = process_delete_req_error();
            break;
        default:
            ERROR_LOG("Invalid command");
            break;
    }

    return ret;
}