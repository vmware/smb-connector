/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#include "base/Log.h"
#include "base/Error.h"
#include "base/Protocol.h"
#include "AddFolderPacketCreator.h"

/*!
 * Constructor
 */
AddFolderPacketCreator::AddFolderPacketCreator()
{
    //Empty Constructor
}

/*!
 * Destructor
 */
AddFolderPacketCreator::~AddFolderPacketCreator()
{
    //Empty Destructor
}

/*!
 * Creates ADD_FOLDER_INIT_REQ packet
 * @param packet - request packet
 * @return
 * SMB_SUCCESS - successful
 * Otherwise - failure
 */
int AddFolderPacketCreator::create_add_folder_req(Packet *packet)
{
    DEBUG_LOG("AddFolderPacketCreator::create_add_folder_req");
    assert(packet != NULL);
    assert(packet->_pb_msg != NULL);

    AddFolderProcessor *_processor = dynamic_cast<AddFolderProcessor *>(RequestProcessor::GetInstance());
    if (IS_NULL(_processor))
    {
        DEBUG_LOG("AddFolderPacketCreator::create_add_folder_req invalid RequestProcessor");
        return SMB_ERROR;
    }

    Command *cmd = ALLOCATE(Command);
    if (!ALLOCATED(cmd))
    {
        DEBUG_LOG("AddFolderPacketCreator::create_add_folder_req, memory allocation failed");
        FREE(packet->_pb_msg);
        return SMB_ALLOCATION_FAILED;
    }

    cmd->set_cmd(ADD_FOLDER_INIT_REQ);
    cmd->set_requestid(_processor->RequestId());
    packet->_pb_msg->set_allocated_command(cmd);
    CreateCredentialPacket(packet);

    packet->PutHeader();
    if (packet->PutData() != SMB_SUCCESS)
    {
        DEBUG_LOG("AddFolderPacketCreator::create_add_folder_req packet creation failed");
        FREE(packet->_pb_msg); /*pb will take care of freeing up all resources contained in it */
        return SMB_ERROR;
    }
    packet->Dump();
    return SMB_SUCCESS;
}

/*!
 * Create ADD_FOLDER_INIT_RESP
 * @param packet
 * @return
 * SMB_SUCCESS - successful
 * Otherwise - failure
 */
int AddFolderPacketCreator::create_add_folder_resp(Packet *packet)
{
    DEBUG_LOG("AddFolderPacketCreator::create_add_folder_resp");
    assert(packet != NULL);

    AddFolderProcessor *_processor = dynamic_cast<AddFolderProcessor *>(RequestProcessor::GetInstance());
    if (IS_NULL(_processor))
    {
        DEBUG_LOG("AddFolderPacketCreator::create_add_folder_resp invalid RequestProcessor");
        return SMB_ERROR;
    }

    Command *cmd = ALLOCATE(Command);
    ResponsePacket *resp = ALLOCATE(ResponsePacket);
    AddFolderResponse *addResp = ALLOCATE(AddFolderResponse);
    FileInformation *fInfo = ALLOCATE(FileInformation);
    if (!ALLOCATED(cmd) || !ALLOCATED(resp) || !ALLOCATED(addResp) || !ALLOCATED(fInfo))
    {
        DEBUG_LOG("AddFolderPacketCreator::create_add_folder_resp, memory allocation failed");
        FREE(cmd);
        FREE(resp);
        FREE(addResp);
        FREE(fInfo);
        FREE(packet->_pb_msg);
        return SMB_ALLOCATION_FAILED;
    }

    /* Command */
    cmd->set_cmd(ADD_FOLDER_INIT_RESP);
    cmd->set_requestid(_processor->RequestId());
    packet->_pb_msg->set_allocated_command(cmd);

    struct stat *ptr = _processor->GetStat();

    assert(ptr != NULL);

    fInfo->set_createtime(ptr->st_ctim.tv_sec);
    fInfo->set_modifiedtime(ptr->st_mtim.tv_sec);

    addResp->set_allocated_fileinformation(fInfo);
    resp->set_allocated_addfolderresponse(addResp);

    packet->_pb_msg->set_allocated_responsepacket(resp);

    packet->PutHeader();
    if (packet->PutData() != SMB_SUCCESS)
    {
        DEBUG_LOG("AddFolderPacketCreator::create_add_folder_resp packet creation failed");
        FREE(packet->_pb_msg); /* will take care of freeing up all resources contained in it */
        return SMB_ERROR;
    }
    packet->Dump();
    return SMB_SUCCESS;
}

/*!
 * Creates packet with op_code
 * @param packet - packet to be filled
 * @param op_code - operation code
 * @param data - op-code specific data
 * @return
 * SMB_SUCCESS - successful
 * Otherwise - Failure
 */
int AddFolderPacketCreator::CreatePacket(Packet *packet, int op_code, void *data)
{
    DEBUG_LOG("AddFolderPacketCreator::CreatePacket");

    if (packet == NULL)
    {
        DEBUG_LOG("AddFolderPacketCreator::CreatePacket, NULL packet");
        return SMB_ERROR;
    }

    packet->_pb_msg = ALLOCATE(Message);
    if (!ALLOCATED(packet->_pb_msg))
    {
        DEBUG_LOG("AddFolderPacketCreator::CreatePacket, memory allocation failed");
        return SMB_ALLOCATION_FAILED;
    }

    switch (op_code)
    {
        case ADD_FOLDER_INIT_REQ:
            return create_add_folder_req(packet);
        case ADD_FOLDER_INIT_RESP:
            return create_add_folder_resp(packet);
        default:
            ERROR_LOG("Invalid op_code");
            FREE(packet->_pb_msg);
            return SMB_ERROR;
    }
}