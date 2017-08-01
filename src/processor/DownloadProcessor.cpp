/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#include <future>

#include "base/Error.h"
#include "base/Log.h"
#include "base/Configuration.h"
#include "base/Protocol.h"
#include "packet/DownloadPacketCreator.h"
#include "packet/DownloadPacketParser.h"

using milli = std::chrono::milliseconds;

/*!
 * Constructor
 */
DownloadProcessor::DownloadProcessor()
{
    //Empty Constructor
}

/*!
 * Destructor
 */
DownloadProcessor::~DownloadProcessor()
{
    //Empty Destructor
}

/*!
 * Process DOWNLOAD_REQ_INIT request
 * @return
 * SMB_SUCCESS    - Successful
 * Otherwise - Failed
 */
int DownloadProcessor::process_download_req_init()
{
    DEBUG_LOG("DownloadProcessor::process_download_req_init");
    SmbClient::GetInstance()->CredentialsInit(_url, _work_group, _user_name, _password);
    int ret = SmbClient::GetInstance()->DownloadInit();
    if (ret != SMB_SUCCESS)
    {
        int err = errno;
        ERROR_LOG("DownloadProcessor::process_download_req_init failed");
        Packet *resp = ALLOCATE(Packet);
        _packet_creator->CreateStatusPacket(resp, DOWNLOAD_ERROR, err, true);
        _sessionManager->PushResponse(resp);
        _sessionManager->ProcessWriteEvent();
        SmbClient::GetInstance()->CloseFile();
        return SMB_ERROR;
    }

    DEBUG_LOG("DownloadProcessor::process_download_req_init success");
    Packet *resp = ALLOCATE(Packet);
    _packet_creator->CreatePacket(resp, DOWNLOAD_INIT_RESP, NULL);
    _sessionManager->PushResponse(resp);
    _sessionManager->ProcessWriteEvent();
    return SMB_SUCCESS;
}

/*!
 * Process DOWNLOAD_REQ_INIT_RESP request
 * @return
 * SMB_SUCCESS    - Successful
 * Otherwise - Failed
 */
int DownloadProcessor::process_download_req_init_resp()
{
    DEBUG_LOG("DownloadProcessor::process_download_req_init_resp");
    Packet *req = ALLOCATE(Packet);
    struct packet_download_req_data param;
    param.start = _start_offset;
    param.end = _end_offset;
    param.chunk_size = atoi(Configuration::GetInstance()[C_UNIX_SOCK_BUFFER]);
    _packet_creator->CreatePacket(req, DOWNLOAD_DATA_REQ, &param);
    _sessionManager->PushResponse(req);
    _sessionManager->ProcessWriteEvent();
    return SMB_SUCCESS;
}

/*!
 * Process DOWNLOAD_REQ_DATA request
 * @return
 * SMB_SUCCESS    - Successful
 * Otherwise - Failed
 */
int DownloadProcessor::process_download_req_data()
{
    DEBUG_LOG("DownloadProcessor::process_download_req_data");
    int ret = SmbClient::GetInstance()->SetOffset(_start_offset, _end_offset);
    if (ret != SMB_SUCCESS)
    {
        DEBUG_LOG("DownloadProcessor::process_download_req_data failed");
        int err = errno;
        Packet *resp = ALLOCATE(Packet);
        _packet_creator->CreateStatusPacket(resp, DOWNLOAD_ERROR, err, true);
        _sessionManager->PushResponse(resp);
        _sessionManager->ProcessWriteEvent();
        return SMB_ERROR;
    }

    DEBUG_LOG("DownloadProcessor::process_download_req_data starting async file download");
    _async_operation = ALLOCATE(std::thread, &DownloadProcessor::download_file_async, this);
    return SMB_SUCCESS;
}

/*!
* Process DOWNLOAD_RESP_DATA request
* @return
* SMB_SUCCESS    - Successful
* Otherwise - Failed
*/
int DownloadProcessor::process_download_resp_data(Packet *packet)
{
    DEBUG_LOG("DownloadProcessor::process_download_resp_data");
    assert(packet != NULL);
    assert(packet->_data != NULL);
    _file.write(packet->_pb_msg->responsepacket().downloaddataresponse().data().c_str(),
                packet->_pb_msg->responsepacket().downloaddataresponse().data().size());
    return SMB_SUCCESS;
}

/*!
* Process DOWNLOAD_RESP_END request
* @return
* SMB_SUCCESS    - Successful
* Otherwise - Failed
*/
int DownloadProcessor::process_download_resp_end()
{
    DEBUG_LOG("DownloadProcessor::process_download_resp_end");
    _file.close();
    Configuration &c = Configuration::GetInstance();
    if (!atoi(c[C_OP_MODE]))
    {
        should_exit = 1;
    }
    return SMB_SUCCESS;
}

/*!
* Process DOWNLOAD_ERROR request
* @return
* SMB_SUCCESS    - Successful
* Otherwise - Failed
*/
int DownloadProcessor::process_download_resp_error()
{
    DEBUG_LOG("DownloadProcessor::process_download_resp_error");
    _file.close();
    Configuration &c = Configuration::GetInstance();
    if (!atoi(c[C_OP_MODE]))
    {
        should_exit = 1;
    }
    return SMB_SUCCESS;
}

/*!
 * Downloads the file from SMB server
 * Create response packet and stores them in response queue
 * @return
 * SMB_SUCCESS    - Successful
 * Otherwise - Failed
 */
int DownloadProcessor::download_file_async()
{
    DEBUG_LOG("DownloadProcessor::DownloadFileAsync");
    Configuration &c = Configuration::GetInstance();
    size_t sent_bytes = 0;
    struct packet_upload_download_data param;
    static auto start = std::chrono::high_resolution_clock::now();
    while (!_should_exit)
    {
        _sessionManager->ResetTimer();
        if (_sessionManager->IsResponseSpaceAvailable())
        {
            /* start downloading the file */
            char data[atoi(c[C_SMB_SOCK_READ_BUFFER])];
            ssize_t ret = SmbClient::GetInstance()->Read(data, sizeof(data));
            if (ret == SMB_SUCCESS)
            {
                static auto finish = std::chrono::high_resolution_clock::now();
                DEBUG_LOG("Time took for Complete Download %ld milliseconds",
                          std::chrono::duration_cast<milli>(finish - start).count());
                INFO_LOG("DownloadProcessor::DownloadFileAsync Download successful Size %ld", sent_bytes);
                Packet *resp = ALLOCATE(Packet);
                _packet_creator->CreatePacket(resp, DOWNLOAD_END_RESP, NULL);
                _sessionManager->PushResponse(resp);
                if (_sessionManager->ProcessWriteEvent() != SMB_SUCCESS)
                {
                    DEBUG_LOG(
                        "DownloadProcessor::download_file_async Download interrupted while sending end packet, bail out");
                }
                return SMB_SUCCESS;
            }
            else if (ret > 0)
            {
                sent_bytes += ret;
                DEBUG_LOG("DownloadProcessor::DownloadFileAsync received bytes: %ld from SmbClient-server", sent_bytes);
                char *tmp = data;
                while (!_should_exit && ret != 0 && tmp != NULL)
                {
                    Packet *resp = ALLOCATE(Packet);
                    uint64_t to_copy = 0;
                    if (static_cast<uint64_t>(ret) > _chunk_size)
                    {
                        to_copy = _chunk_size;
                    }
                    else
                    {
                        to_copy = ret;
                    }
                    param.payload = tmp;
                    param.payload_len = to_copy;
                    _packet_creator->CreatePacket(resp, DOWNLOAD_DATA_RESP, &param);
                    _sessionManager->PushResponse(resp);
                    if (_sessionManager->ProcessWriteEvent() != SMB_SUCCESS)
                    {
                        DEBUG_LOG("DownloadProcessor::download_file_async Download interrupted, bail out");
                        return SMB_ERROR;
                    }
                    tmp += to_copy;
                    ret -= to_copy;
                }
            }
            else
            {
                DEBUG_LOG("DownloadProcessor::DownloadFileAsync Download error");
                DEBUG_LOG("DownloadProcessor::DownloadFileAsync SmbClient-server %s closed the connection",
                          _url.c_str());
                int err = errno;
                Packet *resp = ALLOCATE(Packet);
                _packet_creator->CreateStatusPacket(resp, DOWNLOAD_ERROR, err, true);
                _sessionManager->PushResponse(resp);
                if (_sessionManager->ProcessWriteEvent() != SMB_SUCCESS)
                {
                    DEBUG_LOG(
                        "DownloadProcessor::download_file_async Download interrupted while fetching data, bail out");
                }
                return SMB_ERROR;
            }
        }
        else
        {
            DEBUG_LOG("DownloadProcessor::download_file_async Buffer full, try to send some data and pause for a while");
            if (_sessionManager->ProcessWriteEvent() != SMB_SUCCESS)
            {
                DEBUG_LOG("Sending data failed, bail out");
                return SMB_ERROR;
            }
            sleep(1);
        }
    }

    return SMB_SUCCESS;

}

/*!
 * Initialisation
 *
 * @param request_id - request_id
 *
 * @return
 * SMB_SUCCESS    - Successful
 * Otherwise - Failed
 */
int DownloadProcessor::Init(std::string &request_id)
{
    DEBUG_LOG("DownloadProcessor::Init");
    _start_offset = 0;
    _end_offset = 0;
    _packet_parser = new DownloadPacketParser();
    _packet_creator = new DownloadPacketCreator();
    RequestProcessor::Init(request_id);
    return SMB_SUCCESS;
}

/*!
 * Process request
 * @param request     - request to be processed
 * @return
 * SMB_SUCCESS    - Successful
 * Otherwise - Failed
 */
int DownloadProcessor::ProcessRequest(Packet *request)
{
    DEBUG_LOG("DownloadProcessor::ProcessRequest");
    assert(request != NULL);
    assert(request->_data != NULL);

    if (request == NULL || request->_data == NULL)
    {
        ERROR_LOG("DownloadProcessor::ProcessRequest NULL packet");
        return SMB_ERROR;
    }

    int ret = _packet_parser->ParsePacket(request);
    if (ret != SMB_SUCCESS)
    {
        DEBUG_LOG("DownloadProcessor::ProcessRequest, invalid packet");
        Packet *resp = ALLOCATE(Packet);
        _packet_creator->CreateStatusPacket(resp, DOWNLOAD_ERROR, ret);
        _sessionManager->PushResponse(resp);
        _sessionManager->ProcessWriteEvent();
        return ret;
    }

    DEBUG_LOG("DownloadProcessor::ProcessRequest Command %s", ProtocolCommand(request->GetCMD()));
    switch (request->GetCMD())
    {
        case DOWNLOAD_INIT_REQ:
            ret = process_download_req_init();
            break;
        case DOWNLOAD_INIT_RESP:
            ret = process_download_req_init_resp();
            break;
        case DOWNLOAD_DATA_REQ:
            ret = process_download_req_data();
            break;
        case DOWNLOAD_DATA_RESP:
            static auto start = std::chrono::high_resolution_clock::now();
            ret = process_download_resp_data(request);
            break;
        case DOWNLOAD_END_RESP:
            ret = process_download_resp_end();
            static auto finish = std::chrono::high_resolution_clock::now();
            DEBUG_LOG("Time took for Complete Download %ld milliseconds",
                      std::chrono::duration_cast<milli>(finish - start).count());
            break;
        case DOWNLOAD_ERROR:
            ret = process_download_resp_error();
            break;
        default:
            ERROR_LOG("Invalid Request");
            ret = SMB_ERROR;
            break;
    }
    return ret;
}

/*!
 * Opens a file to store downloaded data
 * Used for client side mocking
 * @return
 * SMB_SUCCESS    - Successful
 * Otherwise - Failed
 */
int DownloadProcessor::OpenFile()
{
    DEBUG_LOG("DownloadProcessor::OpenFile");
    _file.open(Configuration::GetInstance()[C_OUT_FILE], std::ios::app);
    return SMB_SUCCESS;
}

/*!
* Return stat structure for file which is to be downloaded
*
* @return
* SMB_SUCCESS    - Successful
* Otherwise - Failed
*/
struct stat *DownloadProcessor::GetStat()
{
    DEBUG_LOG("DownloadProcessor::GetStat");
    return SmbClient::GetInstance()->FileStat();
}

/*!
* setter function for start offset
*/
void DownloadProcessor::SetStartOffset(unsigned int _start_offset)
{
    DownloadProcessor::_start_offset = _start_offset;
}

/*!
* setter function for end offset
*/
void DownloadProcessor::SetEndOffset(unsigned int _end_offset)
{
    DownloadProcessor::_end_offset = _end_offset;
}

/*!
* getter function for file size
* @return
* size
*/
int DownloadProcessor::Size() const
{
    return _size;
}

/*!
* setter function for file size
*/
void DownloadProcessor::SetSize(int _size)
{
    DownloadProcessor::_size = _size;
}

/*!
* getter function for create-time of file
*
* @return
* create-time
*/
const uint64_t &DownloadProcessor::CreateTime() const
{
    return _c_time;
}

/*!
* setter function for create-time of file
*/
void DownloadProcessor::SetCreateTime(const uint64_t &_c_time)
{
    DownloadProcessor::_c_time = _c_time;
}

/*!
* getter function for modify-time of file
*
* @return
* modified-time
*/
const uint64_t &DownloadProcessor::ModifiedTime() const
{
    return _m_time;
}

/*!
* setter function for modify-time of file
*/
void DownloadProcessor::SetModifiedTime(const uint64_t &_m_time)
{
    DownloadProcessor::_m_time = _m_time;
}

/*!
* setter function for chunk-size of file
*/
void DownloadProcessor::SetChunkSize(uint64_t _chunk_size)
{
    DownloadProcessor::_chunk_size = _chunk_size;
}
