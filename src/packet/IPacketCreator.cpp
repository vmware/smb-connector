/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#include "IPacketCreator.h"
#include "base/Log.h"
#include "base/Error.h"
#include "processor/RequestProcessor.h"

/*!
 * Constructor
 */
IPacketCreator::IPacketCreator()
{
    //Constructor
}

/*!
 * Destrcutor
 */
IPacketCreator::~IPacketCreator()
{
    //Destructor
}

/*!
 *
 * Create status packet
 * @param packet - request packet
 * @param status_code - status code
 * @param smbc_status - status from libsmbclient
 *
 * @return
 *      SMB_SUCCESS - Successful
 *      SMB_ALLOCATION_FAILED - Failed
 */

int IPacketCreator::CreateStatusPacket(Packet *packet, int cmd, int status_code, bool smbc_status)
{
    DEBUG_LOG("IPacketCreator::CreateErrorPacket");
    assert(packet != NULL);
    assert(RequestProcessor::GetInstance()->RequestId().length() > 0);

    if (packet == NULL)
    {
        ERROR_LOG("IPacketCreator::CreateErrorPacket, null packet");
        return SMB_ERROR;
    }

    packet->_pb_msg = ALLOCATE(Message);
    Command *command = ALLOCATE(Command);
    Status *status = ALLOCATE(Status);

    if (!ALLOCATED(packet->_pb_msg) || !ALLOCATED(command) || !ALLOCATED(status))
    {
        ERROR_LOG("IPacketCreator::CreateErrorPacket, memory allocation failed");
        FREE(packet->_pb_msg);
        FREE(command);
        FREE(status);
        return SMB_ALLOCATION_FAILED;
    }

    /*Status*/
    status->set_code(status_code);
    if (!smbc_status)
    {
        status->set_msg(GetError(status_code));
    }
    else
    {
        status->set_msg(strerror(status_code));
    }

    /*Command*/
    command->set_requestid(RequestProcessor::GetInstance()->RequestId());
    command->set_cmd(cmd);


    packet->_pb_msg->set_allocated_status(status);
    packet->_pb_msg->set_allocated_command(command);

    packet->PutHeader();
    if (packet->PutData() != SMB_SUCCESS)
    {
        ERROR_LOG("IPacketCreator::CreateErrorPacket packet creation failed");
        FREE(packet->_pb_msg);
        return SMB_ERROR;
    }
    packet->Dump();

    INFO_LOG("Error details: CMD:%d, err-code:%d, err-string: %s", cmd, status->code(), status->msg().c_str());
    return SMB_SUCCESS;
}

/*!
 * Creates credentials packet (used for client side mocking)
 * @param obj
 * @return
 * SMB_SUCCESS - success
 * Otherwise  - failure
 */
int IPacketCreator::CreateCredentialPacket(Packet *obj)
{
    assert(obj != NULL);
    assert(obj->_pb_msg != NULL);

    //Ownership is transferred to protocol-buffers
    SmbDetails *smbDetails = ALLOCATE(SmbDetails);
    if (!ALLOCATED(smbDetails))
    {
        ERROR_LOG("IPacketCreator::CreateCredentialPacket memory allocation failed");
        return SMB_ALLOCATION_FAILED;
    }
    smbDetails->set_workgroup(RequestProcessor::GetInstance()->WorkGroup());
    smbDetails->set_username(RequestProcessor::GetInstance()->UserName());
    smbDetails->set_password(RequestProcessor::GetInstance()->Password());
    smbDetails->set_url(RequestProcessor::GetInstance()->Url());
    smbDetails->set_kerberos(RequestProcessor::GetInstance()->Kerberos());
    obj->_pb_msg->mutable_requestpacket()->set_allocated_smbdetails(smbDetails);

    return SMB_SUCCESS;
}
