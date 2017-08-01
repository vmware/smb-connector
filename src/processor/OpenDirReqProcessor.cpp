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
#include "packet/OpenDirPacketCreator.h"
#include "packet/OpenDirReqPacketParser.h"


/*!
 * Constructor
 */
OpenDirReqProcessor::OpenDirReqProcessor()
{
    _pageSize = 0;
    _show_hidden_files = false;
    _show_only_folders = false;
    _fetch_share = false;
    _is_directory = true;
}

/*!
 * Destructor
 */
OpenDirReqProcessor::~OpenDirReqProcessor()
{
    //Destructor
}

/*!
 * Process GET_STRUCTURE_INIT_REQ packet
 * @return
 * SMB_SUCCESS - Successful
 * Otherwise   - failure
 */
int OpenDirReqProcessor::process_get_structure_req()
{
    DEBUG_LOG("OpenDirReqProcessor::process_get_structure_req");
    SmbClient::GetInstance()->CredentialsInit(_url, _work_group, _user_name, _password);
    int ret = SmbClient::GetInstance()->OpenDir();
    if (ret != SMB_SUCCESS)
    {
        DEBUG_LOG("OpenDirReqProcessor::process_get_structure_req, open as directory failed for %s", _url.c_str());
        int err = errno;
        if (err == ENOTDIR || err == EINVAL)
        {
            _is_directory = false;
            DEBUG_LOG("OpenDirReqProcessor::process_get_structure_req open it as file");
            ret = SmbClient::GetInstance()->OpenFile(O_RDONLY);
            if (ret != SMB_SUCCESS)
            {
                DEBUG_LOG("OpenDirReqProcessor::process_get_structure_req open as file failed for %s", _url.c_str());
                err = errno;
                Packet *req = ALLOCATE(Packet);
                _packet_creator->CreateStatusPacket(req, GET_STRUCTURE_ERROR_RESP, err, true);
                _sessionManager->PushResponse(req);
                _sessionManager->ProcessWriteEvent();
                return SMB_ERROR;
            }
        }
        else
        {
            Packet *req = ALLOCATE(Packet);
            _packet_creator->CreateStatusPacket(req, GET_STRUCTURE_ERROR_RESP, err, true);
            _sessionManager->PushResponse(req);
            _sessionManager->ProcessWriteEvent();
            return SMB_ERROR;
        }
    }
    else
    {
        _is_directory = true;
    }

    DEBUG_LOG("OpenDirReqProcessor::process_get_structure_req start sending the list for %s", _url.c_str());
    _async_operation = ALLOCATE(std::thread, &OpenDirReqProcessor::send_list_async, this);

    return SMB_SUCCESS;
}

/*!
 * Process GET_STRUCTURE_INIT_RESP packet
 * @return
 * SMB_SUCCESS - Successful
 * Otherwise - failure
 */
int OpenDirReqProcessor::process_get_structure_req_resp()
{
    DEBUG_LOG("OpenDirReqProcessor::process_get_structure_req_resp");
    return SMB_SUCCESS;
}

/*!
 * Process GET_STRUCTURE_END_RESP packet
 * @return
 * SMB_SUCCESS - Successful
 * Otherwise - failure
 */
int OpenDirReqProcessor::process_get_structure_resp_end()
{
    DEBUG_LOG("OpenDirReqProcessor::process_get_structure_resp_end");
    Configuration &c = Configuration::GetInstance();
    if (!atoi(c[C_OP_MODE]))
        should_exit = 1;
    return SMB_SUCCESS;
}

/*!
 * Process GET_STRUCTURE_ERROR_RESP packet
 * @return
 * SMB_SUCCESS - Successful
 * Otherwise - Failure
 */
int OpenDirReqProcessor::process_get_structure_req_error()
{
    DEBUG_LOG("OpenDirReqProcessor::process_get_structure_req_error");
    Configuration &c = Configuration::GetInstance();
    if (!atoi(c[C_OP_MODE]))
        should_exit = 1;
    return SMB_SUCCESS;
}

/*!
 * Fetches the file list in other thread
 * prepare response packet
 * Add them to response queue
 * @return
 * SMB_SUCCESS - All files list sent
 * Otherwise - failure
 */
int OpenDirReqProcessor::send_list_async()
{
    DEBUG_LOG("OpenDirReqProcessor::send_list_async");
    while (!_should_exit)
    {
        Packet *req = ALLOCATE(Packet);
        int ret = _packet_creator->CreatePacket(req, GET_STRUCTURE_INIT_RESP, NULL);
        if (ret == SMB_SUCCESS)
        {
            if (!_is_directory)
            {
                _sessionManager->PushResponse(req);
                _sessionManager->ProcessWriteEvent();
                req = ALLOCATE(Packet);
            }
            /* Sent all list, Send a GET_STRUCTURE_END_RESP packet */
            DEBUG_LOG("OpenDirReqProcessor::send_list_async, all list sent, send <end> packet");
            _packet_creator->CreatePacket(req, GET_STRUCTURE_END_RESP, NULL);
            SmbClient::GetInstance()->CloseDir();
            _sessionManager->PushResponse(req);
            _sessionManager->ProcessWriteEvent();

            break;
        }
        else if (ret == SMB_AGAIN)
        {
            DEBUG_LOG("OpenDirReqProcessor::send_list_async, sending list for %s", _url.c_str());
            _sessionManager->PushResponse(req);
            if (_sessionManager->ProcessWriteEvent() != SMB_SUCCESS)
            {
                DEBUG_LOG("OpenDirReqProcessor::send_list_async send failed, abprt now");
                return SMB_ERROR;
            }
        }
        else
        {
            FREE(req);
            SmbClient::GetInstance()->CloseDir();
            return SMB_ERROR;
        }
    }

    return SMB_SUCCESS;
}

/*!
 * Initialise OpenDirReqProcessor
 * @param request-id - request-id
 * @return
 * SMB_SUCCESS - Successful
 * Otherwise   - failure
 */
int OpenDirReqProcessor::Init(std::string &request_id)
{
    DEBUG_LOG("OpenDirReqProcessor::Init");
    _packet_parser = new OpenDirPacketParser();
    _packet_creator = new OpenDirPacketCreator();
    RequestProcessor::Init(request_id);
    return SMB_SUCCESS;
}

/*!
 * Process all incoming request for list-directory
 * @param request - request packet
 * @return
 * SMB_SUCCESS - Successful
 * Otherwise   - failure
 */
int OpenDirReqProcessor::ProcessRequest(Packet *request)
{
    DEBUG_LOG("OpenDirReqProcessor::ProcessRequest");
    assert(request != NULL);
    assert(request->_data != NULL);

    if (request == NULL || request->_data == NULL)
    {
        ERROR_LOG("OpenDirReqProcessor::ProcessRequest NULL packet");
        return SMB_ERROR;
    }

    int ret = _packet_parser->ParsePacket(request);
    if (ret != SMB_SUCCESS)
    {
        DEBUG_LOG("OpenDirReqProcessor::ProcessRequest invalid packet");
        Packet *req = ALLOCATE(Packet);
        _packet_creator->CreateStatusPacket(req, GET_STRUCTURE_ERROR_RESP, ret);
        _sessionManager->PushResponse(req);
        _sessionManager->ProcessWriteEvent();
        return ret;
    }

    DEBUG_LOG("OpenDirReqProcessor::ProcessRequest Command %s", ProtocolCommand(request->GetCMD()));
    switch (request->GetCMD())
    {
        case GET_STRUCTURE_INIT_REQ:
            ret = process_get_structure_req();
            break;
        case GET_STRUCTURE_INIT_RESP:
            ret = process_get_structure_req_resp();
            break;
        case GET_STRUCTURE_END_RESP:
            ret = process_get_structure_resp_end();
            break;
        case GET_STRUCTURE_ERROR_RESP:
            ret = process_get_structure_req_error();
            break;
        default:
            ret = SMB_ERROR;
            ERROR_LOG("Invalid GET_STR packet");
            break;
    }


    return ret;
}

/*!
 * Iterate file-list for a directory and return all attributes
 * @return
 * struct file_info - Success
 * NULL - list traversed
 */
struct file_info *OpenDirReqProcessor::GetFileInfo()
{
    DEBUG_LOG("OpenDirReqProcessor::GetFileInfo");
    return SmbClient::GetInstance()->GetNextFileInfo();
}

/*!
 * returns stat structure when queried for file
 * Calling this method over a folder will return garbage data
 * @return
 * stat structure
 */
struct stat *OpenDirReqProcessor::GetStat()
{
    DEBUG_LOG("OpenDirReqProcessor::GetStat");
    return SmbClient::GetInstance()->FileStat();
}

/*!
 * Iterate share-list for a smb-server and return smbc_dirent
 * @return
 * struct smbc_dirent - Success
 * NULL - list traversed
 */

struct smbc_dirent *OpenDirReqProcessor::GetDirent()
{
    return SmbClient::GetInstance()->GetNextDirent();
}

/*!
 * getter for show_only_folder flag
 * @return
 */
bool OpenDirReqProcessor::ShowOnlyFolders() const
{
    return _show_only_folders;
}

/*!
 * setter for show_only_folder flag
 */
void OpenDirReqProcessor::SetShowOnlyFolders(bool show_only_folders)
{
    OpenDirReqProcessor::_show_only_folders = show_only_folders;
}

/*!
 * getter for show_hidden_files flag
 * @return
 */
bool OpenDirReqProcessor::ShowHiddenFiles() const
{
    return _show_hidden_files;
}

/*!
 * setter for show_hidden_files flag
 */
void OpenDirReqProcessor::SetShowHiddenFiles(bool show_hidden_files)
{
    OpenDirReqProcessor::_show_hidden_files = show_hidden_files;
}

/*!
 * getter for page_size
 * @return
 */
int OpenDirReqProcessor::PageSize() const
{
    return _pageSize;
}

/*!
 * setter for page_size
 */
void OpenDirReqProcessor::SetPageSize(int _pageSize)
{
    OpenDirReqProcessor::_pageSize = _pageSize;
}

/*!
 * Is directory
 * @return
 */
bool OpenDirReqProcessor::IsDirectory() const
{
    return _is_directory;
}

/*!
 * Set is_directory
 * @param is_directory
 */
void OpenDirReqProcessor::SetIsDirectory(bool is_directory)
{
    OpenDirReqProcessor::_is_directory = is_directory;
}

/*!
 * Should fetch share information
 * @return
 */
bool OpenDirReqProcessor::FetchShare() const
{
    return _fetch_share;
}

/*!
 * Set fetch-share flag
 * @param _fetch_share
 */
void OpenDirReqProcessor::SetFetchShare(bool _fetch_share)
{
    OpenDirReqProcessor::_fetch_share = _fetch_share;
}
