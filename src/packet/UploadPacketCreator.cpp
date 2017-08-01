/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#include "base/Log.h"
#include "base/Error.h"
#include "base/Protocol.h"
#include "UploadPacketCreator.h"

/*!
 * Constructor
 */
UploadPacketCreator::UploadPacketCreator()
{
    //Empty Constructor
}

/*!
 * Destructor
 */
UploadPacketCreator::~UploadPacketCreator()
{
    //Empty Destructor
}

/*!
 * Create UPLOAD_REQ_INIT packet
 * @param packet - request packet
 * @return
 *      SMB_SUCCESS - Successful
 *      Otherwise - Failed
 */
int UploadPacketCreator::create_upload_req_init(Packet *packet)
{
    DEBUG_LOG("UploadPacketCreator::create_upload_req_init");
    assert(packet != NULL);
    assert(packet->_pb_msg != NULL);

    UploadProcessor *_processor = dynamic_cast<UploadProcessor *>(RequestProcessor::GetInstance());
    if (IS_NULL(_processor))
    {
        DEBUG_LOG("UploadPacketCreator::create_upload_req_init invalid RequestProcessor");
        return SMB_ERROR;
    }

    Command *cmd = ALLOCATE(Command);
    if (!ALLOCATED(cmd))
    {
        DEBUG_LOG("UploadPacketCreator::create_upload_req_init, memory allocation failed");
        FREE(packet->_pb_msg);
        return SMB_ALLOCATION_FAILED;
    }

    cmd->set_cmd(UPLOAD_INIT_REQ);
    cmd->set_requestid(_processor->RequestId());
    packet->_pb_msg->set_allocated_command(cmd);
    CreateCredentialPacket(packet);

    packet->PutHeader();
    if (packet->PutData() != SMB_SUCCESS)
    {
        DEBUG_LOG("UploadPacketCreator::create_upload_req_init packet creation failed");
        FREE(packet->_pb_msg); /*pb will take care of freeing up all resources contained in it */
        return SMB_ERROR;
    }
    packet->Dump();

    return SMB_SUCCESS;
}

/*!
 * Create UPLOAD_REQ_DATA packet
 * @param packet - request packet
 * @param buffer - data to be put in packet
 * @param len    - length of data-buffer
 * @return
 *      SMB_SUCCESS - Successful
 *      Otherwise - Failed
 */
int UploadPacketCreator::create_upload_req_data(Packet *packet, packet_data *data)
{
    DEBUG_LOG("UploadPacketCreator::create_upload_req_data");
    assert(packet != NULL);
    assert(packet->_pb_msg != NULL);
    assert(data->download_upload_data.payload != NULL);

    UploadProcessor *_processor = dynamic_cast<UploadProcessor *>(RequestProcessor::GetInstance());
    if (IS_NULL(_processor))
    {
        DEBUG_LOG("UploadPacketCreator::create_upload_req_data invalid RequestProcessor");
        return SMB_ERROR;
    }

    Command *cmd = ALLOCATE(Command);
    RequestPacket *req = ALLOCATE(RequestPacket);
    UploadRequestData *u_req = ALLOCATE(UploadRequestData);

    if (!ALLOCATED(cmd) || !ALLOCATED(req) || !ALLOCATED(u_req))
    {
        DEBUG_LOG("UploadPacketCreator::create_upload_req_data, memory allocation failed");
        FREE(cmd);
        FREE(req);
        FREE(u_req);
        FREE(packet->_pb_msg);
        return SMB_ALLOCATION_FAILED;
    }

    cmd->set_requestid(_processor->RequestId());
    cmd->set_cmd(UPLOAD_DATA_REQ);
    packet->_pb_msg->set_allocated_command(cmd);

    u_req->set_data(data->download_upload_data.payload, data->download_upload_data.payload_len);
    req->set_allocated_uploadrequestdata(u_req);
    packet->_pb_msg->set_allocated_requestpacket(req);

    packet->PutHeader();
    if (packet->PutData() != SMB_SUCCESS)
    {
        DEBUG_LOG("UploadPacketCreator::create_upload_req_data packet creation failed");
        FREE(packet->_pb_msg); /*pb will take care of freeing up all resources contained in it */
        return SMB_ERROR;
    }
    packet->Dump();

    return SMB_SUCCESS;
}

/*!
 * Create UPLOAD_REQ_DATA_END packet
 * @param packet - request object
 * @return
 * SMB_SUCCESS - successful
 * Otherwise - failure
 */
int UploadPacketCreator::create_upload_req_end(Packet *packet)
{
    DEBUG_LOG("UploadPacketCreator::create_upload_req_data");
    assert(packet != NULL);
    assert(packet->_pb_msg != NULL);

    UploadProcessor *_processor = dynamic_cast<UploadProcessor *>(RequestProcessor::GetInstance());
    if (IS_NULL(_processor))
    {
        DEBUG_LOG("UploadPacketCreator::create_upload_req_end invalid RequestProcessor");
        return SMB_ERROR;
    }

    Command *cmd = ALLOCATE(Command);
    if (!ALLOCATED(cmd))
    {
        DEBUG_LOG("UploadPacketCreator::create_upload_req_end, memory allocation failed");
        FREE(packet->_pb_msg);
        return SMB_ALLOCATION_FAILED;
    }

    /*Command*/
    cmd->set_cmd(UPLOAD_END_REQ);
    cmd->set_requestid(_processor->RequestId());
    packet->_pb_msg->set_allocated_command(cmd);

    packet->PutHeader();
    if (packet->PutData() != SMB_SUCCESS)
    {
        DEBUG_LOG("UploadPacketCreator::create_upload_req_end packet creation failed");
        FREE(packet->_pb_msg); /*pb will take care of freeing up all resources contained in it */
        return SMB_ERROR;
    }
    packet->Dump();

    return SMB_SUCCESS;
}

/*!
 * Create packet for uplaod module
 * @param packet - outgoing packet
 * @param op_code - operation code
 * @param data - additional data
 * @return
 *      SMB_SUCCESS - Successful
 *      Otherwise - Failed
 */
int UploadPacketCreator::CreatePacket(Packet *packet, int op_code, void *data)
{
    DEBUG_LOG("UploadPacketCreator::CreatePacket");
    if (packet == NULL)
    {
        DEBUG_LOG("UploadPacketCreator::CreatePacket, NULL packet");
        return SMB_ERROR;
    }

    packet->_pb_msg = ALLOCATE(Message);
    if (!ALLOCATED(packet->_pb_msg))
    {
        DEBUG_LOG("UploadPacketCreator::CreatePacket, memory allocation failed");
        return SMB_ALLOCATION_FAILED;
    }

    switch (op_code)
    {
        case UPLOAD_INIT_REQ:
            return create_upload_req_init(packet);
        case UPLOAD_DATA_REQ:
        {
            if (data == NULL)
            {
                DEBUG_LOG("UploadPacketCreator::CreatePacket, data missing for UPLOAD_REQ_DATA");
                return SMB_ERROR;
            }
            return create_upload_req_data(packet, static_cast<packet_data *>(data));
        }
        case UPLOAD_END_REQ:
            return create_upload_req_end(packet);
        default:
            FREE(packet->_pb_msg);
            ERROR_LOG("Invalid op_code");
            break;
    }

    return SMB_ERROR;
}