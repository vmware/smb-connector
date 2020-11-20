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
#include "packet/UploadPacketCreator.h"
#include "packet/UploadPacketParser.h"

using milli = std::chrono::milliseconds;

/*!
 * Constructor
 */
UploadProcessor::UploadProcessor()
{
    _bytes_uploaded = 0;
    _upload_success = false;
}

/*!
 * Destructor
 */
UploadProcessor::~UploadProcessor()
{
    //Empty Destructor
}

/*!
 * Process UPLOAD_REQ_INIT request
 * @return
 * SMB_SUCCESS - Successful
 * Otherwise - failure
 */
int UploadProcessor::process_upload_req_init()
{
    DEBUG_LOG("UploadProcessor::process_upload_req_init");
    SmbClient::GetInstance()->CredentialsInit(_url, _work_group, _user_name, _password);
    int ret = SmbClient::GetInstance()->UploadInit(_request_id);
    if (ret != SMB_SUCCESS)
    {
        ERROR_LOG("UploadProcessor::process_upload_req_init failed for %s, return error", _url.c_str());
        int err = errno;
        Packet *resp = ALLOCATE(Packet);
        _packet_creator->CreateStatusPacket(resp, UPLOAD_ERROR, err, true);
        _sessionManager->PushResponse(resp);
        _sessionManager->ProcessWriteEvent();
        return SMB_ERROR;
    }

    Packet *resp = ALLOCATE(Packet);
    _packet_creator->CreateStatusPacket(resp, UPLOAD_INIT_RESP, 0);
    _sessionManager->PushResponse(resp);
    _sessionManager->ProcessWriteEvent();

    DEBUG_LOG("UploadProcessor::process_upload_req_init success for %s", _url.c_str());
    return SMB_SUCCESS;
}

/*!
 * Process UPLOAD_REQ_INIT_RESP
 * @return
 * SMB_SUCCESS - Successful
 * Otherwise - failure
 */
int UploadProcessor::process_upload_req_init_resp()
{
    DEBUG_LOG("UploadProcessor::process_upload_req_init_resp");
    DEBUG_LOG("UploadProcessor::process_upload_req_init_resp start async upload");
    _async_operation = ALLOCATE(std::thread, &UploadProcessor::upload_async, this);
    return SMB_SUCCESS;
}

/*!
 * Process UPLOAD_REQ_DATA
 * @param packet
 * @return
 * SMB_SUCCESS - Successful
 * Otherwise - failure
 */
int UploadProcessor::process_upload_req_data(Packet *packet)
{
    DEBUG_LOG("UploadProcessor::process_upload_req_data");
    int ret = SmbClient::GetInstance()->Write(
        const_cast<char *>(packet->_pb_msg->requestpacket().uploadrequestdata().data().c_str()),
        packet->_pb_msg->requestpacket().uploadrequestdata().data().size());

    if (ret < 0)
    {
        /* smb_write failed */
        /* delete the tmp file */
        int err = errno;
        ERROR_LOG("UploadProcessor::process_upload_req_data upload failed, SmbClient-server[%s] closed connection",
                  _url.c_str());
        Packet *req = ALLOCATE(Packet);
        _packet_creator->CreateStatusPacket(req, UPLOAD_ERROR, err, true);
        _sessionManager->PushResponse(req);
        _sessionManager->ProcessWriteEvent();
        return SMB_ERROR;
    }

    _bytes_uploaded += ret;
    DEBUG_LOG("UploadProcessor::process_upload_req_data total upload so far %d", _bytes_uploaded);
    return SMB_SUCCESS;
}

/*!
 * Process UPLOAD_REQ_DATA_ERROR
 * @return
 * SMB_SUCCESS - Successful
 * Otherwise - failure
 */
int UploadProcessor::process_upload_req_data_error()
{
    DEBUG_LOG("UploadProcessor::process_upload_req_data_error Upload error");
    Configuration &c = Configuration::GetInstance();
    if(!atoi(c[C_FILE_UPLOAD_MODE]))
    {
    SmbClient::GetInstance()->DelTmpFile();
    }
    if (!atoi(c[C_OP_MODE]))
    {
        should_exit = 1;
    }
    return SMB_SUCCESS;
}

/*!
 * Process UPLOAD_REQ_DATA_END
 * @return
 * SMB_SUCCESS - Successful
 * Otherwise - failure
 */
int UploadProcessor::process_upload_req_data_end()
{
    DEBUG_LOG("UploadProcessor::process_upload_req_data_end");
    _bytes_uploaded = 0;
    SmbClient::GetInstance()->CloseFile();
    Configuration &c = Configuration::GetInstance();
    if(!atoi(c[C_FILE_UPLOAD_MODE]))
    {
    SmbClient::GetInstance()->RestoreTmpFile(_request_id);
    }
    Packet *resp = ALLOCATE(Packet);
    _packet_creator->CreateStatusPacket(resp, UPLOAD_END_RESP, 0);
    _sessionManager->PushResponse(resp);
    _sessionManager->ProcessWriteEvent();
    _upload_success = true;
    return SMB_SUCCESS;
}

/*!
 * Process UPLOAD_REQ_DATA_RESP
 * @return
 * SMB_SUCCESS - Successful
 * Otherwise - failure
 */
int UploadProcessor::process_upload_req_data_resp()
{
    DEBUG_LOG("UploadProcessor::process_upload_req_data_resp");
    Configuration &c = Configuration::GetInstance();
    if (!atoi(c[C_OP_MODE]))
    {
        should_exit = 1;
    }
    return SMB_SUCCESS;
}

/*!
 * Upload file
 * @return
 * SMB_SUCCESS - Successful
 * Otherwise - failure
 */
int UploadProcessor::upload_async()
{
    DEBUG_LOG("UploadProcessor::upload_async");
    int read_bytes = 0;
    int total_bytes = 0;
    Packet *req = NULL;
    Configuration &c = Configuration::GetInstance();

    struct packet_upload_download_data param;

    if (!_file.is_open())
    {
        ERROR_LOG("UploadProcessor::upload_async file open failed, send error");
        req = ALLOCATE(Packet);
        _packet_creator->CreateStatusPacket(req, UPLOAD_ERROR, SMB_NOT_FOUND);
        _sessionManager->PushResponse(req);
        _sessionManager->ProcessWriteEvent();
        return SMB_ERROR;
    }

    while (!_should_exit)
    {
        if (_sessionManager->IsResponseSpaceAvailable())
        {
            req = ALLOCATE(Packet);
            char buffer[atoi(c[C_SMB_SOCK_WRITE_BUFFER])];
            memset(buffer, 0, sizeof(buffer));
            read_bytes = (int) _file.readsome(buffer, sizeof(buffer));
            if (read_bytes <= 0)
            {
                break;
            }
            param.payload = buffer;
            param.payload_len = read_bytes;
            _packet_creator->CreatePacket(req, UPLOAD_DATA_REQ, &param);
            total_bytes += read_bytes;
            _sessionManager->PushResponse(req);
            if (_sessionManager->ProcessWriteEvent() != SMB_SUCCESS)
            {
                WARNING_LOG("UploadProcessir::upload_async send failed, bail out");
                return SMB_ERROR;
            }
        }
        else
        {
            INFO_LOG("UploadProcessor::upload_async Buffer full, pause for a while");
            sleep(1);
            continue;
        }
    }

    if (!_should_exit)
    {
        _packet_creator->CreatePacket(req, UPLOAD_END_REQ, NULL);
        _sessionManager->PushResponse(req);
        _sessionManager->ProcessWriteEvent();
        DEBUG_LOG("UploadProcessor::upload_async upload success, total bytes uploaded %d", total_bytes);
    }
    return SMB_SUCCESS;
}

/*!
 * Initialisation
 * @param request_id - request id
 * @return
 * SMB_SUCCESS - Successful
 * Otherwise - failure
 */
int UploadProcessor::Init(std::string &request_id)
{
    DEBUG_LOG("UploadProcessor::Init");
    _bytes_uploaded = 0;
    _packet_parser = new UploadPacketParser();
    _packet_creator = new UploadPacketCreator();
    RequestProcessor::Init(request_id);
    return SMB_SUCCESS;
}

/*!
 * Process Request packet for upload module
 * @param request - request-id
 * @return
 * SMB_SUCCESS - Successful
 * Otherwise - failure
 */
int UploadProcessor::ProcessRequest(Packet *request)
{
    DEBUG_LOG("UploadProcessor::ProcessRequest");
    assert(request != NULL);
    assert(request->_data != NULL);

    if (request == NULL || request->_data == NULL)
    {
        ERROR_LOG("UploadProcessor::ProcessRequest NULL packet");
        return SMB_ERROR;
    }

    int ret = _packet_parser->ParsePacket(request);
    if (ret != SMB_SUCCESS)
    {
        ERROR_LOG("UploadProcessor::ProcessRequest packet parsing failed, return error");
        Packet *resp = ALLOCATE(Packet);
        _packet_creator->CreateStatusPacket(resp, UPLOAD_ERROR, ret);
        _sessionManager->PushResponse(resp);
        _sessionManager->ProcessWriteEvent();
        return ret;
    }

    DEBUG_LOG("UploadProcessor::ProcessRequest Command %s", ProtocolCommand(request->GetCMD()));
    switch (request->GetCMD())
    {
        case UPLOAD_INIT_REQ:
            static auto start = std::chrono::high_resolution_clock::now();
            ret = process_upload_req_init();
            break;
        case UPLOAD_INIT_RESP:
            ret = process_upload_req_init_resp();
            break;
        case UPLOAD_DATA_REQ:
            ret = process_upload_req_data(request);
            break;
        case UPLOAD_ERROR:
            ret = process_upload_req_data_error();
            break;
        case UPLOAD_END_REQ:
        {
            ret = process_upload_req_data_end();
            static auto finish = std::chrono::high_resolution_clock::now();
            DEBUG_LOG("Time took for Complete Upload %ld milliseconds",
                      std::chrono::duration_cast<milli>(finish - start).count());
            break;
        }
        case UPLOAD_END_RESP:
            ret = process_upload_req_data_resp();
            break;
        default:
            ret = SMB_ERROR;
            ERROR_LOG("Invalid UPLOAD_REQ packet");
            break;
    }

    return ret;
}

/*!
 * Cleanup
 */
void UploadProcessor::Quit()
{
    DEBUG_LOG("UploadProcessor::Quit");
    Configuration &c = Configuration::GetInstance();
    if (!atoi(c[C_FILE_UPLOAD_MODE]) && !_upload_success)
    {
        SmbClient::GetInstance()->DelTmpFile();
    }
    RequestProcessor::Quit();
}

/*!
 * Open file which has to be uploaded (client-side mocking)
 */
void UploadProcessor::OpenFile()
{
    DEBUG_LOG("UploadProcessor::OpenFile");
    _upload_success = true; // disable restore on client side
    _file.open(Configuration::GetInstance()[C_OUT_FILE], std::ios::app);
}
