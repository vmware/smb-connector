/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#include "base/Error.h"
#include "base/Log.h"
#include "base/Protocol.h"
#include "DeletePacketCreator.h"

/*!
 * Constructor
 */
DeletePacketCreator::DeletePacketCreator()
{
    //Empty Constructor
}

/*!
 * Destructor
 */
DeletePacketCreator::~DeletePacketCreator()
{
    //Empty Destructor
}

/*!
 * Creates DELETE_INIT_REQ Packet
 * @param packet - request packet
 * @return
 * SMB_SUCCESS - successful
 * Otherwise - failure
 */
int DeletePacketCreator::create_delete_req(Packet *packet)
{
    DEBUG_LOG("DeletePacketCreator::create_delete_req");
    assert(packet != NULL);
    assert(packet->_pb_msg != NULL);

    DeleteProcessor *_processor = dynamic_cast<DeleteProcessor *>(RequestProcessor::GetInstance());
    if (IS_NULL(_processor))
    {
        DEBUG_LOG("DeletePacketCreator::create_delete_req invalid RequestProcessor");
        return SMB_ERROR;
    }

    Command *cmd = ALLOCATE(Command);
    if (!ALLOCATED(cmd))
    {
        DEBUG_LOG("DeletePacketCreator::create_delete_req, memory allocation failed");
        FREE(packet->_pb_msg);
        return SMB_ALLOCATION_FAILED;
    }
    cmd->set_cmd(DELETE_INIT_REQ);
    cmd->set_requestid(_processor->RequestId());
    packet->_pb_msg->set_allocated_command(cmd);
    CreateCredentialPacket(packet);

    packet->PutHeader();
    if (packet->PutData() != SMB_SUCCESS)
    {
        DEBUG_LOG("DeletePacketCreator::create_delete_req packet creation failed");
        FREE(packet->_pb_msg); /*pb will take care of freeing up all resources contained in it */
        return SMB_ERROR;
    }
    packet->Dump();
    return SMB_SUCCESS;
}

/*!
 * Creates DELETE_INIT_RESP packet
 * @param packet - request packet
 * @return
 * SMB_SUCCESS - successful
 * Otherwise - failure
 */
int DeletePacketCreator::create_delete_resp(Packet *packet, packet_data *data)
{
    assert(packet != NULL);
    assert(packet->_pb_msg != NULL);

    DeleteProcessor *_processor = dynamic_cast<DeleteProcessor *>(RequestProcessor::GetInstance());
    if (IS_NULL(_processor))
    {
        DEBUG_LOG("DeletePacketCreator::create_delete_resp invalid RequestProcessor");
        return SMB_ERROR;
    }

    Command *cmd = ALLOCATE(Command);
    ResponsePacket *resp = ALLOCATE(ResponsePacket);
    DeleteResourceResponse *delResp = ALLOCATE(DeleteResourceResponse);
    FileInformation *fInfo = ALLOCATE(FileInformation);
    if (!ALLOCATED(cmd) || !ALLOCATED(resp) || !ALLOCATED(delResp) || !ALLOCATED(fInfo))
    {
        DEBUG_LOG("DeletePacketCreator::create_delete_resp, memory allocation failed");
        FREE(cmd);
        FREE(resp);
        FREE(delResp);
        FREE(fInfo);
        FREE(packet->_pb_msg);
        return SMB_ALLOCATION_FAILED;
    }

    /* Command */
    cmd->set_cmd(DELETE_INIT_RESP);
    cmd->set_requestid(_processor->RequestId());
    packet->_pb_msg->set_allocated_command(cmd);

    /* File info */
    fInfo->set_isdirectory(data->delete_resp.is_directory);
    delResp->set_allocated_fileinformation(fInfo);
    resp->set_allocated_deleteresourceresponse(delResp);

    /* ResponsePacket */
    packet->_pb_msg->set_allocated_responsepacket(resp);
    packet->PutHeader();
    if (packet->PutData() != SMB_SUCCESS)
    {
        DEBUG_LOG("DeletePacketCreator::create_delete_resp packet creation failed");
        FREE(packet->_pb_msg); /*pb will take care of freeing up all resources contained in it */
        return SMB_ERROR;
    }
    packet->Dump();
    return SMB_SUCCESS;
}

/*!
 * Creates packet with corresponding op_code
 * @param packet - packet to be filled
 * @param op_code - operation code
 * @param data - operation specific data
 * @return
 * SMB_SUCCESS - successful
 * Otherwise - failure
 */
int DeletePacketCreator::CreatePacket(Packet *packet, int op_code, void *data)
{
    DEBUG_LOG("DeletePacketCreator::CreatePacket");

    if (packet == NULL)
    {
        DEBUG_LOG("DeletePacketCreator::CreatePacket, NULL packet");
        return SMB_ERROR;
    }

    packet->_pb_msg = ALLOCATE(Message);
    if (!ALLOCATED(packet->_pb_msg))
    {
        DEBUG_LOG("DeletePacketCreator::CreatePacket, memory allocation failed");
        return SMB_ALLOCATION_FAILED;
    }

    switch (op_code)
    {
        case DELETE_INIT_REQ:
            return create_delete_req(packet);
        case DELETE_INIT_RESP:
        {
            if (data == NULL)
            {
                DEBUG_LOG("DeletePacketCreator::CreatePacket, data missing for DELETE_INIT_RESP");
                return SMB_ERROR;
            }
            return create_delete_resp(packet, static_cast<packet_data *>(data));
        }
        default:
            ERROR_LOG("Invalid op_code");
            FREE(packet->_pb_msg);
            return SMB_ERROR;
    }
}