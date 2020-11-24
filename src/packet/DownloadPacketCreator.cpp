/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#include "base/Log.h"
#include "base/Error.h"
#include "base/Protocol.h"
#include "DownloadPacketCreator.h"

/*!
 * Constructor
 */
DownloadPacketCreator::DownloadPacketCreator()
{
    //Empty Constructor
}

/*!
 * Destructor
 */
DownloadPacketCreator::~DownloadPacketCreator()
{
    //Empty Destructor
}

/*!
 * Create
 * @param packet DOWNLOAD_INIT_REQ packet
 * @return
 *      SMB_SUCCESS - Successful
 *      Otherwise - Failed
 */
int DownloadPacketCreator::create_download_req_init(Packet *packet)
{
    DEBUG_LOG("DownloadPacketCreator::create_download_req_init");
    assert(packet != NULL);
    assert(packet->_pb_msg != NULL);

    DownloadProcessor *_processor = dynamic_cast<DownloadProcessor *>(RequestProcessor::GetInstance());
    if (IS_NULL(_processor))
    {
        ERROR_LOG("DownloadPacketCreator::create_download_req_init invalid RequestProcessor");
        return SMB_ERROR;
    }

    Command *cmd = ALLOCATE(Command);
    if (!ALLOCATED(cmd))
    {
        ERROR_LOG("DownloadPacketCreator::create_download_req_init, memory allocation failed");
        FREE(packet->_pb_msg);
        return SMB_ALLOCATION_FAILED;
    }

    cmd->set_cmd(DOWNLOAD_INIT_REQ);
    cmd->set_requestid(_processor->RequestId());
    packet->_pb_msg->set_allocated_command(cmd);
    CreateCredentialPacket(packet);

    packet->PutHeader();
    if (packet->PutData() != SMB_SUCCESS)
    {
        ERROR_LOG("DownloadPacketCreator::create_download_req_init packet creation failed");
        FREE(packet->_pb_msg); /*pb will take care of freeing up all resources contained in it */
        return SMB_ERROR;
    }
    packet->Dump();

    return SMB_SUCCESS;
}

/*!
 *
 * Create DOWNLOAD_INIT_RESP packet
 * @param packet = request packet
 *
 * @return
 *      SMB_SUCCESS - Successful
 *      Otherwise - Failed
 */
int DownloadPacketCreator::create_download_req_init_resp(Packet *packet)
{
    DEBUG_LOG("DownloadPacketCreator::create_download_req_init_resp");
    assert(packet != NULL);
    assert(packet->_pb_msg != NULL);

    DownloadProcessor *_processor = dynamic_cast<DownloadProcessor *>(RequestProcessor::GetInstance());
    if (IS_NULL(_processor))
    {
        ERROR_LOG("DownloadPacketCreator::create_download_req_init_resp invalid RequestProcessor");
        return SMB_ERROR;
    }

    Command *cmd = ALLOCATE(Command);
    ResponsePacket *resp = ALLOCATE(ResponsePacket);
    DownloadInitResponse *dResp = ALLOCATE(DownloadInitResponse);
    FileInformation *fInfo = ALLOCATE(FileInformation);
    if (!ALLOCATED(cmd) || !ALLOCATED(resp) || !ALLOCATED(dResp) || !ALLOCATED(fInfo))
    {
        ERROR_LOG("DownloadPacketCreator::create_download_req_init_resp, memory allocation failed");
        FREE(cmd);
        FREE(resp);
        FREE(dResp);
        FREE(fInfo);
        FREE(packet->_pb_msg);
        return SMB_ALLOCATION_FAILED;
    }

    /*Command*/
    cmd->set_cmd(DOWNLOAD_INIT_RESP);
    cmd->set_requestid(_processor->RequestId());
    packet->_pb_msg->set_allocated_command(cmd);

    /*File Info*/
    struct stat *ptr = NULL;
    ptr = _processor->GetStat();
    assert(ptr != NULL);
    fInfo->set_size(ptr->st_size);
    fInfo->set_createtime(ptr->st_ctim.tv_sec);
    fInfo->set_modifiedtime(ptr->st_mtim.tv_sec);
    dResp->set_allocated_fileinformation(fInfo);

    /*DownloadInitResponse*/
    resp->set_allocated_downloadinitresponse(dResp);
    packet->_pb_msg->set_allocated_responsepacket(resp);

    packet->PutHeader();
    if (packet->PutData() != SMB_SUCCESS)
    {
        ERROR_LOG("DownloadPacketCreator::create_download_req_init_resp packet creation failed");
        FREE(packet->_pb_msg); /*pb will take care of freeing up all resources contained in it */
        return SMB_ERROR;
    }
    packet->Dump();

    return SMB_SUCCESS;
}

/*!
 * Create DOWNLOAD_DATA_REQ packet
 * @param packet - request packet
 * @param data - operation specific data
 * @return
 *      SMB_SUCCESS - Successful
 *      Otherwise - Failed
 */
int DownloadPacketCreator::create_download_req_data(Packet *packet, packet_data *data)
{
    DEBUG_LOG("DownloadPacketCreator::create_download_req_data");
    assert(packet != NULL);
    assert(packet->_pb_msg != NULL);

    DownloadProcessor *_processor = dynamic_cast<DownloadProcessor *>(RequestProcessor::GetInstance());
    if (IS_NULL(_processor))
    {
        ERROR_LOG("DownloadPacketCreator::create_download_req_data invalid RequestProcessor");
        return SMB_ERROR;
    }

    Command *cmd = ALLOCATE(Command);
    RequestPacket *req = ALLOCATE(RequestPacket);
    RangeDownloadRequest *download_req = ALLOCATE(RangeDownloadRequest);
    if (!ALLOCATED(cmd) || !ALLOCATED(req) || !ALLOCATED(download_req))
    {
        ERROR_LOG("DownloadPacketCreator::create_download_req_data, memory allocation failed");
        FREE(cmd);
        FREE(req);
        FREE(download_req);
        FREE(packet->_pb_msg);
        return SMB_ALLOCATION_FAILED;
    }

    /*Command*/
    cmd->set_cmd(DOWNLOAD_DATA_REQ);
    cmd->set_requestid(_processor->RequestId());
    packet->_pb_msg->set_allocated_command(cmd);

    /*RangeDownloadRequest*/
    download_req->set_start(data->dowload_req_data.start);
    download_req->set_end(data->dowload_req_data.end);
    download_req->set_chunksize(data->dowload_req_data.chunk_size);
    req->set_allocated_rangedownloadrequest(download_req);
    packet->_pb_msg->set_allocated_requestpacket(req);

    packet->PutHeader();
    if (packet->PutData() != SMB_SUCCESS)
    {
        ERROR_LOG("DownloadPacketCreator::create_download_req_init_resp packet creation failed");
        FREE(packet->_pb_msg); /*pb will take care of freeing up all resources contained in it */
        return SMB_ERROR;
    }
    packet->Dump();

    return SMB_SUCCESS;
}

/*!
 *
 * Create DOWNLOAD_DATA_RESP packet
 * @param packet - request packet
 * @param payload - byte stream
 * @param payload_len - size of byte stream
 *
 * @return
 *      SMB_SUCCESS - Successful
 *      Otherwise - Failed
 */
int DownloadPacketCreator::create_download_resp_data(Packet *packet, packet_data *data)
{
    DEBUG_LOG("DownloadPacketCreator::create_download_resp_data");
    assert(packet != NULL);
    assert(packet->_pb_msg != NULL);
    assert(data->download_upload_data.payload != NULL);

    DownloadProcessor *_processor = dynamic_cast<DownloadProcessor *>(RequestProcessor::GetInstance());
    if (IS_NULL(_processor))
    {
        ERROR_LOG("DownloadPacketCreator::create_download_resp_data invalid RequestProcessor");
        return SMB_ERROR;
    }

    Command *cmd = ALLOCATE(Command);
    ResponsePacket *resp = ALLOCATE(ResponsePacket);
    DownloadDataResponse *d_resp = ALLOCATE(DownloadDataResponse);
    if (!ALLOCATED(cmd) || !ALLOCATED(resp) || !ALLOCATED(d_resp))
    {
        ERROR_LOG("DownloadPacketCreator::create_download_resp_data, memory allocation failed");
        FREE(cmd);
        FREE(resp);
        FREE(d_resp);
        FREE(packet->_pb_msg);
        return SMB_ALLOCATION_FAILED;
    }

    /*Command*/
    cmd->set_cmd(DOWNLOAD_DATA_RESP);
    cmd->set_requestid(_processor->RequestId());
    packet->_pb_msg->set_allocated_command(cmd);

    /*DownloadDataResponse*/
    d_resp->set_data(data->download_upload_data.payload, data->download_upload_data.payload_len);
    resp->set_allocated_downloaddataresponse(d_resp);
    packet->_pb_msg->set_allocated_responsepacket(resp);

    packet->PutHeader();
    if (packet->PutData() != SMB_SUCCESS)
    {
        ERROR_LOG("DownloadPacketCreator::create_download_resp_data packet creation failed");
        FREE(packet->_pb_msg); /*pb will take care of freeing up all resources contained in it */
        return SMB_ERROR;
    }
    packet->Dump();

    return SMB_SUCCESS;
}

/*!
 *
 * Create DOWNLOAD_END_RESP packet
 * @param packet - request packet
 *
 * @return
 *      SMB_SUCCESS - Successful
 *      Otherwise - Failed
 */
int DownloadPacketCreator::create_download_resp_end(Packet *packet)
{
    DEBUG_LOG("DownloadPacketCreator::create_download_resp_end");
    assert(packet != NULL);
    assert(packet->_pb_msg != NULL);

    DownloadProcessor *_processor = dynamic_cast<DownloadProcessor *>(RequestProcessor::GetInstance());
    if (IS_NULL(_processor))
    {
        ERROR_LOG("DownloadPacketCreator::create_download_resp_end invalid RequestProcessor");
        return SMB_ERROR;
    }

    /*Command*/
    Command *cmd = ALLOCATE(Command);
    if (!ALLOCATED(cmd))
    {
        ERROR_LOG("DownloadPacketCreator::create_download_resp_data, memory allocation failed");
        FREE(cmd);
        FREE(packet->_pb_msg);
        return SMB_ALLOCATION_FAILED;
    }
    cmd->set_cmd(DOWNLOAD_END_RESP);
    cmd->set_requestid(_processor->RequestId());

    packet->_pb_msg->set_allocated_command(cmd);
    packet->PutHeader();
    if (packet->PutData() != SMB_SUCCESS)
    {
        ERROR_LOG("DownloadPacketCreator::create_download_resp_end packet creation failed");
        FREE(packet->_pb_msg); /*pb will take care of freeing up all resources contained in it */
        return SMB_ERROR;
    }
    packet->Dump();

    return SMB_SUCCESS;
}

/*!
 * Creates packet with op_code
 * @param packet - packet to be filled up
 * @param op_code - operation code
 * @param data - additional data for operation code
 * @return
 * SMB_SUCCESS - successful
 * Otherwise - failure
 */
int DownloadPacketCreator::CreatePacket(Packet *packet, int op_code, void *data)
{
    DEBUG_LOG("DownloadPacketCreator::CreatePacket");
    if (packet == NULL)
    {
        ERROR_LOG("DownloadPacketCreator::CreatePacket, NULL packet");
        return SMB_ERROR;
    }

    packet->_pb_msg = ALLOCATE(Message);
    if (!ALLOCATED(packet->_pb_msg))
    {
        ERROR_LOG("DownloadPacketCreator::CreatePacket, memory allocation failed");
        return SMB_ALLOCATION_FAILED;
    }

    switch (op_code)
    {
        case DOWNLOAD_INIT_REQ:
            return create_download_req_init(packet);
        case DOWNLOAD_INIT_RESP:
            return create_download_req_init_resp(packet);
        case DOWNLOAD_DATA_REQ:
            if (data == NULL)
            {
                ERROR_LOG("DownloadPacketCreator::CreatePacket, data missing for DOWNLOAD_DATA_REQ");
                return SMB_ERROR;
            }
            return create_download_req_data(packet, static_cast<packet_data *>(data));
        case DOWNLOAD_DATA_RESP:
            if (data == NULL)
            {
                ERROR_LOG("DownloadPacketCreator::CreatePacket, data missing for DOWNLOAD_DATA_RESP");
                return SMB_ERROR;
            }
            return create_download_resp_data(packet, static_cast<packet_data *>(data));
        case DOWNLOAD_END_RESP:
            return create_download_resp_end(packet);
        default:
            FREE(packet->_pb_msg);
            packet->_pb_msg = NULL;
            ERROR_LOG("Invalid op_code");
            break;
    }

    return SMB_ERROR;
}
