/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#include "base/Error.h"
#include "base/Log.h"
#include "base/Protocol.h"
#include "TestConnectionPacketCreator.h"

/*!
 * Constructor
 */
TestConnectionPacketCreator::TestConnectionPacketCreator()
{
    //Constructor
}

/*!
 * Destructor
 */
TestConnectionPacketCreator::~TestConnectionPacketCreator()
{
    //Destructor
}

/*!
 * Creates TEST_CONNECTION_INIT_REQ packet
 * @param packet - request packet
 * @return
 * SMB_SUCCESS - successful
 * Otherwise - failure
 */
int TestConnectionPacketCreator::create_test_connection_req(Packet *packet)
{
    DEBUG_LOG("TestConnectionPacketCreator::create_test_connection_req");
    assert(packet != NULL);
    assert(packet->_pb_msg != NULL);

    TestConnection *_processor = dynamic_cast<TestConnection *>(RequestProcessor::GetInstance());
    if (IS_NULL(_processor))
    {
        ERROR_LOG("TestConnectionPacketCreator::create_test_connection_req invalid RequestProcessor");
        return SMB_ERROR;
    }

    Command *cmd = ALLOCATE(Command);
    if (!ALLOCATED(cmd))
    {
        ERROR_LOG("TestConnectionPacketCreator::create_test_connection_req, memory allocation failed");
        FREE(packet->_pb_msg);
        return SMB_ALLOCATION_FAILED;
    }
    cmd->set_cmd(TEST_CONNECTION_INIT_REQ);
    cmd->set_requestid(_processor->RequestId());
    packet->_pb_msg->set_allocated_command(cmd);

    CreateCredentialPacket(packet);

    packet->PutHeader();
    if (packet->PutData() != SMB_SUCCESS)
    {
        ERROR_LOG("TestConnectionPacketCreator::create_test_connection_req packet creation failed");
        FREE(packet->_pb_msg); /*pb will take care of freeing up all resources contained in it */
        return SMB_ERROR;
    }
    packet->Dump();
    return SMB_SUCCESS;
}

/*!
 * Creates TEST_CONNECTION_INIT_RESP packet
 * @param packet - request packet
 * @return
 * SMB_SUCCESS - successful
 * Otherwise - failure
 */
int TestConnectionPacketCreator::create_test_connection_resp(Packet *packet)
{
    DEBUG_LOG("TestConnectionPacketCreator::create_test_connection_resp");
    assert(packet != NULL);
    assert(packet->_pb_msg != NULL);

    TestConnection *_processor = dynamic_cast<TestConnection *>(RequestProcessor::GetInstance());
    if (IS_NULL(_processor))
    {
        ERROR_LOG("TestConnectionPacketCreator::create_test_connection_resp invalid RequestProcessor");
        return SMB_ERROR;
    }

    Command *cmd = ALLOCATE(Command);
    ResponsePacket *resp = ALLOCATE(ResponsePacket);
    TestConnectionResponse *t_resp = ALLOCATE(TestConnectionResponse);
    FileInformation *f_info = ALLOCATE(FileInformation);
    if (!ALLOCATED(cmd) || !ALLOCATED(resp) || !ALLOCATED(t_resp) || !ALLOCATED(f_info))
    {
        ERROR_LOG("TestConnectionPacketCreator::create_test_connection_resp, memory allocation failed");
        FREE(cmd);
        FREE(resp);
        FREE(t_resp);
        FREE(f_info);
        FREE(packet->_pb_msg);
        return SMB_ALLOCATION_FAILED;
    }
    cmd->set_cmd(TEST_CONNECTION_INIT_RESP);
    cmd->set_requestid(_processor->RequestId());
    packet->_pb_msg->set_allocated_command(cmd);

    const struct libsmb_file_info *ptr = _processor->GetFileInfo();
    struct stat *st = _processor->GetStat();
    if (ptr && strcmp(ptr->name, ".") == 0)
    {
        f_info->set_name(
            _processor->Url().substr(_processor->Url().find_last_of('/') + 1, _processor->Url().length()));
        f_info->set_isdirectory(ptr->attrs & FILE_ATTRIBUTE_DIRECTORY);
        f_info->set_size(ptr->size);
        f_info->set_createtime(ptr->btime_ts.tv_sec*SEC_TO_MS + ptr->btime_ts.tv_nsec*NANO_TO_MS);
        f_info->set_modifiedtime(ptr->mtime_ts.tv_sec*SEC_TO_MS + ptr->mtime_ts.tv_nsec*NANO_TO_MS);
    }
    else if (st)
    {
        f_info->set_name(
            _processor->Url().substr(_processor->Url().find_last_of('/') + 1, _processor->Url().length()));
        f_info->set_isdirectory(st->st_mode & FILE_ATTRIBUTE_DIRECTORY);
        f_info->set_size(st->st_size);
        f_info->set_createtime(st->st_ctim.tv_sec*SEC_TO_MS + st->st_ctim.tv_nsec*NANO_TO_MS);
        f_info->set_modifiedtime(st->st_mtim.tv_sec*SEC_TO_MS + st->st_mtim.tv_nsec*NANO_TO_MS);
    }
    else
    {
        ERROR_LOG("TestConnectionPacketCreator::create_test_connection_resp connection success but no share provided");
        f_info->set_name("");
        f_info->set_isdirectory(0);
        f_info->set_size(0);
        f_info->set_createtime(0);
        f_info->set_modifiedtime(0);
    }


    t_resp->set_allocated_fileinformation(f_info);
    resp->set_allocated_testconnectionresponse(t_resp);
    packet->_pb_msg->set_allocated_responsepacket(resp);

    /*Construct Packet */
    packet->PutHeader();
    if (packet->PutData() != SMB_SUCCESS)
    {
        ERROR_LOG("TestConnectionPacketCreator::create_test_connection_resp packet creation failed");
        FREE(packet->_pb_msg); /*pb will take care of freeing up all resources contained in it */
        return SMB_ERROR;
    }
    packet->Dump();

    return SMB_SUCCESS;
}

/*!
 * Creates packet for list-share module
 * @param packet - out packet
 * @param op_code - operation code
 * @param data - additional data
 * @return
 * SMB_SUCCESS - successful
 * Otherwise - failure
 */
int TestConnectionPacketCreator::CreatePacket(Packet *packet, int op_code, void *data)
{
    DEBUG_LOG("TestConnectionPacketCreator::CreatePacket");
    if (packet == NULL)
    {
        ERROR_LOG("TestConnectionPacketCreator::CreatePacket, NULL packet");
        return SMB_ERROR;
    }

    packet->_pb_msg = ALLOCATE(Message);
    if (!ALLOCATED(packet->_pb_msg))
    {
        ERROR_LOG("TestConnectionPacketCreator::CreatePacket, memory allocation failed");
        return SMB_ALLOCATION_FAILED;
    }

    switch (op_code)
    {
        case TEST_CONNECTION_INIT_REQ:
            return create_test_connection_req(packet);
        case TEST_CONNECTION_INIT_RESP:
            return create_test_connection_resp(packet);
        default:
            ERROR_LOG("invalid op_code");
            FREE(packet->_pb_msg);
            break;
    }
    return SMB_ERROR;
}
