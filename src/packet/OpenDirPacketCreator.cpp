/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#include "base/Error.h"
#include "base/Log.h"
#include "base/Protocol.h"
#include "OpenDirPacketCreator.h"


/*!
 * Constructor
 */
OpenDirPacketCreator::OpenDirPacketCreator()
{
    //Empty constructor
}

/*!
 * Destructor
 */
OpenDirPacketCreator::~OpenDirPacketCreator()
{
    //Empty destructor
}

/*!
 * Creates GET_STRUCTURE_INIT_REQ packet
 * @param packet - request packet
 * @return
 * SMB_SUCCESS - successful
 * Otherwise - failure
 */
int OpenDirPacketCreator::create_get_structure_req(Packet *packet)
{
    DEBUG_LOG("OpenDirPacketCreator::create_get_structure_req");
    assert(packet != NULL);
    assert(packet->_pb_msg != NULL);

    OpenDirReqProcessor *_processor = dynamic_cast<OpenDirReqProcessor *>(RequestProcessor::GetInstance());
    if (IS_NULL(_processor))
    {
        ERROR_LOG("OpenDirPacketCreator::create_get_structure_req invalid RequestProcessor");
        return SMB_ERROR;
    }

    Command *cmd = ALLOCATE(Command);
    RequestPacket *req = ALLOCATE(RequestPacket);
    FolderStructureRequest *f_req = ALLOCATE(FolderStructureRequest);
    if (!ALLOCATED(cmd) || !ALLOCATED(req) || !ALLOCATED(f_req))
    {
        ERROR_LOG("OpenDirPacketCreator::create_get_structure_req, memory allocation failed");
        FREE(cmd);
        FREE(req);
        FREE(f_req);
        FREE(packet->_pb_msg);
        return SMB_ALLOCATION_FAILED;
    }

    /*Command*/
    cmd->set_cmd(GET_STRUCTURE_INIT_REQ);
    cmd->set_requestid(_processor->RequestId());
    packet->_pb_msg->set_allocated_command(cmd);

    packet->_pb_msg->set_allocated_requestpacket(req);
    CreateCredentialPacket(packet);

    f_req->set_pagesize(_processor->PageSize());
    f_req->set_showonlyfolders(_processor->ShowOnlyFolders());
    f_req->set_showhiddenfiles(_processor->ShowHiddenFiles());
    req->set_allocated_folderstructurerequest(f_req);

    packet->PutHeader();
    if (packet->PutData() != SMB_SUCCESS)
    {
        ERROR_LOG("OpenDirPacketCreator::create_get_structure_req packet creation failed");
        FREE(packet->_pb_msg); /*pb will take care of freeing up all resources contained in it */
        return SMB_ERROR;
    }
    packet->Dump();

    return SMB_SUCCESS;
}

/*!
 *
 * Create GET_STRUCTURE_REQ_RESP
 * @param packet - request packet
 *
 * @return
 *      SMB_SUCCESS - Successful
 *      SMB_ALLOCATION_FAILED - Failed
 */

int OpenDirPacketCreator::create_get_structure_resp(Packet *packet)
{
    DEBUG_LOG("OpenDirPacketCreator::create_get_structure_resp");
    assert(packet != NULL);
    assert(packet->_pb_msg != NULL);

    OpenDirReqProcessor *_processor = dynamic_cast<OpenDirReqProcessor *>(RequestProcessor::GetInstance());
    if (IS_NULL(_processor))
    {
        ERROR_LOG("OpenDirPacketCreator::create_get_structure_resp invalid RequestProcessor");
        return SMB_ERROR;
    }

    const struct libsmb_file_info *ptr = NULL;
    struct smbc_dirent *dirent = NULL;
    Command *cmd = ALLOCATE(Command);
    ResponsePacket *resp = ALLOCATE(ResponsePacket);
    FolderStructureResponse *f_resp = ALLOCATE(FolderStructureResponse);
    FileInformation *f_info = NULL;
    if (!ALLOCATED(cmd) || !ALLOCATED(resp) || !ALLOCATED(f_resp))
    {
        ERROR_LOG("OpenDirPacketCreator::create_get_structure_resp, memory allocation failed");
        FREE(cmd);
        FREE(resp);
        FREE(f_resp);
        FREE(packet->_pb_msg);
        return SMB_ALLOCATION_FAILED;
    }

    /*Command*/
    cmd->set_cmd(GET_STRUCTURE_INIT_RESP);
    cmd->set_requestid(_processor->RequestId());
    packet->_pb_msg->set_allocated_command(cmd);

    if (!_processor->IsDirectory())
    {
        INFO_LOG("Probably a file was passed");
        struct stat *st = _processor->GetStat();
        f_info = f_resp->add_fileinformation();
        f_info->set_name(_processor->Url().substr(_processor->Url().find_last_of('/') + 1, _processor->Url().length()));
        f_info->set_isdirectory(false);
        f_info->set_size(st->st_size);
        f_info->set_modifiedtime(st->st_mtim.tv_sec*SEC_TO_MS + st->st_mtim.tv_nsec*NANO_TO_MS);
    }
    else
    {
        for (int i = 0; i < _processor->PageSize(); ++i)
        {
            if (!_processor->FetchShare())
            {
                ptr = _processor->GetFileInfo();

                /* filter smb-connector created tmp files */
                /* Perform a check for folder */
                /* Perform a check for hidden files */
                if (ptr && (strcmp(ptr->name, ".smbconnector") == 0 ||
                    (!(ptr->attrs & FILE_ATTRIBUTE_DIRECTORY) && _processor->ShowOnlyFolders()) ||
                    (ptr->attrs & FILE_ATTRIBUTE_HIDDEN && !_processor->ShowHiddenFiles())))
                {
                    --i;
                    continue;
                }

                if (ptr)
                {
                    f_info = f_resp->add_fileinformation();
                    f_info->set_name(ptr->name);
                    f_info->set_isdirectory(ptr->attrs & FILE_ATTRIBUTE_DIRECTORY);
                    f_info->set_resourcetype(ptr->attrs);
                    f_info->set_size(ptr->size);
                    f_info->set_createtime(ptr->btime_ts.tv_sec*SEC_TO_MS + ptr->btime_ts.tv_nsec*NANO_TO_MS);
                    f_info->set_modifiedtime(ptr->mtime_ts.tv_sec*SEC_TO_MS + ptr->mtime_ts.tv_nsec*NANO_TO_MS);
                }
                else if (i > 0)
                {
                    break;
                }
                else
                {
                    FREE(resp);
                    FREE(f_resp);
                    FREE(packet->_pb_msg);
                    return SMB_SUCCESS;
                }
            }
            else
            {
                dirent = _processor->GetDirent();

                if (dirent)
                {
                    f_info = f_resp->add_fileinformation();
                    f_info->set_name(dirent->name, dirent->namelen);
                    f_info->set_resourcetype(dirent->smbc_type);
                }
                else if (i > 0)
                {
                    break;
                }
                else
                {
                    FREE(resp);
                    FREE(f_resp);
                    FREE(packet->_pb_msg);
                    return SMB_SUCCESS;
                }
            }
        }
    }

    resp->set_allocated_folderstructureresponse(f_resp);
    packet->_pb_msg->set_allocated_responsepacket(resp);

    /*Construct Packet */
    packet->PutHeader();
    if (packet->PutData() != SMB_SUCCESS)
    {
        ERROR_LOG("OpenDirPacketCreator::create_get_structure_req packet creation failed");
        FREE(packet->_pb_msg); /*pb will take care of freeing up all resources contained in it */
        return SMB_ERROR;
    }
    packet->Dump();

    if (!_processor->IsDirectory())
    {
        return SMB_SUCCESS;
    }

    return SMB_AGAIN;
}

/*!
 *
 * Create GET_STRUCTURE_RESP_END packet
 * @param packet - request packet
 *
 * @return
 *      SMB_SUCCESS - Successful
 */
int OpenDirPacketCreator::create_get_structure_end(Packet *packet)
{
    DEBUG_LOG("OpenDirPacketCreator::create_get_structure_end");
    assert(packet != NULL);
    assert(packet->_pb_msg != NULL);


    OpenDirReqProcessor *_processor = dynamic_cast<OpenDirReqProcessor *>(RequestProcessor::GetInstance());
    if (IS_NULL(_processor))
    {
        ERROR_LOG("OpenDirPacketCreator::create_get_structure_end invalid RequestProcessor");
        return SMB_ERROR;
    }

    Command *cmd = ALLOCATE(Command);
    if (!ALLOCATED(cmd))
    {
        ERROR_LOG("OpenDirPacketCreator::create_get_structure_end, memory allocation failed");
        FREE(packet->_pb_msg);
        return SMB_ALLOCATION_FAILED;
    }

    /*Command*/
    cmd->set_requestid(_processor->RequestId());
    cmd->set_cmd(GET_STRUCTURE_END_RESP);
    packet->_pb_msg->set_allocated_command(cmd);

    packet->PutHeader();
    if (packet->PutData() != SMB_SUCCESS)
    {
        ERROR_LOG("OpenDirPacketCreator::create_get_structure_end packet creation failed");
        FREE(packet->_pb_msg); /*pb will take care of freeing up all resources contained in it */
        return SMB_ERROR;
    }
    packet->Dump();
    return SMB_SUCCESS;
}

/*!
 * Create packets for get struture module
 * @param packet - outgoing packet
 * @param op_code - operation code
 * @param data - additional data
 * @return
 * SMB_SUCCESS - successful
 * Otherwise - failure
 */
int OpenDirPacketCreator::CreatePacket(Packet *packet, int op_code, void *data)
{
    DEBUG_LOG("OpenDirPacketCreator::CreatePacket");
    if (packet == NULL)
    {
        ERROR_LOG("OpenDirPacketCreator::CreatePacket, NULL packet");
        return SMB_ERROR;
    }

    packet->_pb_msg = ALLOCATE(Message);
    if (!ALLOCATED(packet->_pb_msg))
    {
        ERROR_LOG("OpenDirPacketCreator::CreatePacket, memory allocation failed");
        return SMB_ALLOCATION_FAILED;
    }

    switch (op_code)
    {
        case GET_STRUCTURE_INIT_REQ:
            return create_get_structure_req(packet);
        case GET_STRUCTURE_INIT_RESP:
            return create_get_structure_resp(packet);
        case GET_STRUCTURE_END_RESP:
            return create_get_structure_end(packet);
        default:
            FREE(packet->_pb_msg);
            ERROR_LOG("Invalid op_code");
            break;
    }
    return SMB_ERROR;
}
