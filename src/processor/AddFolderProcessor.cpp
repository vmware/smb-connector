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
#include "packet/AddFolderPacketCreator.h"
#include "packet/AddFolderPacketParser.h"

/*!
 * Constructor
 */
AddFolderProcessor::AddFolderProcessor()
{
    //Constructor
}

/*!
 * Destructor
 */
AddFolderProcessor::~AddFolderProcessor()
{
    //Destructor
}

/*!
 * Process add folder request from client,
 * adds a folder for share at SMB server machine
 * @return
 * SMB_SUCCESS - Success
 * Otherwise - Failure
 */
int AddFolderProcessor::process_add_folder_req()
{
    DEBUG_LOG("AddFolderProcessor::process_add_folder_req");
    SmbClient::GetInstance()->CredentialsInit(_url, _work_group, _user_name, _password);
    int ret = SmbClient::GetInstance()->CreateDirectory();

    if (ret != SMB_SUCCESS)
    {
        ERROR_LOG("AddFolderProcessor::process_add_folder_req add folder %s failed", _url.c_str());
        ret = errno;
        Packet *resp = ALLOCATE(Packet);
        _packet_creator->CreateStatusPacket(resp, ADD_FOLDER_ERROR_RESP, ret, true);
        _sessionManager->PushResponse(resp);
        _sessionManager->ProcessWriteEvent();
        return SMB_ERROR;
    }

    Packet *resp = ALLOCATE(Packet);
    _packet_creator->CreatePacket(resp, ADD_FOLDER_INIT_RESP, NULL);
    _sessionManager->PushResponse(resp);
    _sessionManager->ProcessWriteEvent();
    DEBUG_LOG("AddFolderProcessor::process_add_folder_req %s folder created", _url.c_str());

    return ret;
}

/*!
 * Process add folder response from smb-connector
 * @return
 * SMB_SUCCESS - Success
 * Otherwise - Failure
 */
int AddFolderProcessor::process_add_folder_req_resp()
{
    DEBUG_LOG("AddFolderProcessor::process_add_folder_req_resp");
    Configuration &c = Configuration::GetInstance();
    if (!atoi(c[C_OP_MODE]))
    {
        should_exit = 1;
    }
    return SMB_SUCCESS;
}

/*!
 * Handles error for add folder request
 * @return
 * SMB_SUCCESS - Success
 * Otherwise - Failure
 */
int AddFolderProcessor::process_add_folder_req_error()
{
    DEBUG_LOG("AddFolderProcessor::process_add_folder_req_error");
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
int AddFolderProcessor::Init(std::string &request_id)
{
    DEBUG_LOG("AddFolderProcessor::Init");
    _packet_parser = new AddFolderPacketParser();
    _packet_creator = new AddFolderPacketCreator();
    return RequestProcessor::Init(request_id);
}

/*!
 * Process all request received from client
 * @param packet - Packet to be processed
 * @return
 * SMB_SUCCESS - Success
 * Otherwise - Failure
 */
int AddFolderProcessor::ProcessRequest(Packet *packet)
{
    DEBUG_LOG("AddFolderProcessor::ProcessRequest");
    assert(packet != NULL);
    assert(packet->_data != NULL);

    if (packet == NULL || packet->_data == NULL)
    {
        ERROR_LOG("AddFolderProcessor::ProcessRequest NULL packet");
        return SMB_ERROR;
    }

    int ret = _packet_parser->ParsePacket(packet);
    if (ret != SMB_SUCCESS)
    {
        DEBUG_LOG("AddFolderProcessor::ProcessRequest Parse Error, Send error");
        Packet *resp = ALLOCATE(Packet);
        _packet_creator->CreateStatusPacket(resp, ADD_FOLDER_ERROR_RESP, ret);
        _sessionManager->PushResponse(resp);
        _sessionManager->ProcessWriteEvent();
        return ret;
    }

    DEBUG_LOG("AddFolderProcessor::ProcessRequest Command %s", ProtocolCommand(packet->GetCMD()));
    switch (packet->GetCMD())
    {
        case ADD_FOLDER_INIT_REQ:
            ret = process_add_folder_req();
            break;
        case ADD_FOLDER_INIT_RESP:
            ret = process_add_folder_req_resp();
            break;
        case ADD_FOLDER_ERROR_RESP:
            ret = process_add_folder_req_error();
            break;
        default:
            ERROR_LOG("Invalid command");
            break;
    }

    return ret;
}

/*!
 * Returns Folder information in stat structure
 * @return
 * stat - Success
 * NULL - failure
 */
struct stat *AddFolderProcessor::GetStat()
{
    DEBUG_LOG("AddFolderProcessor::GetStat");
    return SmbClient::GetInstance()->FileStat();
}