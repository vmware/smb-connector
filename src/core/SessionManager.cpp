/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#include "base/Log.h"
#include "base/Error.h"
#include "base/Protocol.h"
#include "processor/OpenDirReqProcessor.h"
#include "processor/DownloadProcessor.h"
#include "processor/UploadProcessor.h"
#include "processor/AddFolderProcessor.h"
#include "processor/DeleteProcessor.h"
#include "processor/TestConnection.h"
#include "Server.h"

extern int should_exit;

/*!
 * Constructor
 */
SessionManager::SessionManager()
{
    _buff_size = 0;
    _processor_thread = NULL;
    _is_ready = false;
    _processor_thread = ALLOCATE(std::thread, &SessionManager::process_request, this);
}

/*!
 * Destructor
 */
SessionManager::~SessionManager()
{
    //Destructor
}

/*!
 * process request from request queue
 * @return
 * SMB_SUCCESS - Successful
 * Otherwise - failure
 */
int SessionManager::process_request()
{
    _is_ready = true;
    while (!should_exit)
    {
        std::unique_lock<std::mutex> lk(_reader_lock);
        TRACE_LOG("SessionManager::process_request Going for wait");
        if (_reader_cond.wait_for(lk, std::chrono::seconds(5)) == std::cv_status::no_timeout)
        {
            ResetTimer();
        }
        TRACE_LOG("woke up");
        while (!should_exit && !_req_queue.empty())
        {
            Packet *packet = NULL;

            {
                std::lock_guard<std::mutex> scoped_lock(_req_queue_mtx);
                packet = _req_queue.front();
                if (packet == NULL || !packet->_complete)
                {
                    TRACE_LOG("SessionManager::process_request Packet is not complete, wait for signal");
                    break;
                }
                _req_queue.pop_front();
            }

            /* Parse Packet */
            TRACE_LOG("SessionManager::process_request ProcessPacket %p", packet);
            if (packet->ParseProtoBuffer() != SMB_SUCCESS)
            {
                ERROR_LOG("SessionManager::process_request Parse failed");
                FREE(packet);
                _reader_lock.unlock();
                break;
            }

            /* Initialise Processor */
            if (RequestProcessor::GetInstance() == NULL && InitProcessor(packet) != SMB_SUCCESS)
            {
                ERROR_LOG("Received invalid first packet, closing the connection");
                FREE(packet);
                _reader_lock.unlock();
                break;
            }

            /* Process Packet */
            if (RequestProcessor::GetInstance()->ProcessRequest(packet) != SMB_SUCCESS)
            {
                ERROR_LOG("SessionManager::process_request Process Packet failed");
                FREE(packet);
                _reader_lock.unlock();
                break;
            }

            FREE(packet);
        }
    }
    INFO_LOG("SessionManager::process_request exiting");
    return SMB_SUCCESS;
}

/*!
 * Signals process_request thread to process a request
 */
void SessionManager::signal_process_request()
{
    DEBUG_LOG("SessionManager::signal_process_request signal");
    std::lock_guard<std::mutex> lk(_reader_lock);
    _reader_cond.notify_all();
}

/*!
 * Initialisation
 * @param sock - client socket which will be used for read/write operation
 * @return
 *      SMB_SUCCESS - successful
 *      Otherwise - error
 */
int SessionManager::Init(ISmbConnector *smbConnector)
{
    DEBUG_LOG("SessionManager::Init");
    assert(smbConnector != NULL);
    Configuration &c = Configuration::GetInstance();
    _buff_size = (unsigned int) std::stoul(c[C_BUFFER_SIZE]);
    _smbConnector = smbConnector;
    _sock = _smbConnector->GetSocket();
    return SMB_SUCCESS;
}

/*!
 * Check if SessionManager is ready to process client
 * @return
 * true
 * false
 */
bool SessionManager::IsReady()
{
    return _is_ready;
}

/*!
 * Initialises appropriate module
 * @param packet - first packet with command
 * @return
 *      SMB_SUCCESS - successful
 *      Otherwise - error
 */
int SessionManager::InitProcessor(Packet *packet)
{
    switch (packet->GetCMD())
    {
        case GET_STRUCTURE_INIT_REQ:
            DEBUG_LOG("Init OpenDirReqProcessor");
            RequestProcessor::SetInstance(ALLOCATE(OpenDirReqProcessor));
            break;
        case DOWNLOAD_INIT_REQ:
            DEBUG_LOG("Init DownloadProcessor");
            RequestProcessor::SetInstance(ALLOCATE(DownloadProcessor));
            break;
        case UPLOAD_INIT_REQ:
            DEBUG_LOG("Init UploadProcessor");
            RequestProcessor::SetInstance(ALLOCATE(UploadProcessor));
            break;
        case ADD_FOLDER_INIT_REQ:
            DEBUG_LOG("Init AddFolderProcessor");
            RequestProcessor::SetInstance(ALLOCATE(AddFolderProcessor));
            break;
        case DELETE_INIT_REQ:
            DEBUG_LOG("Init DeleteProcessor");
            RequestProcessor::SetInstance(ALLOCATE(DeleteProcessor));
            break;
        case TEST_CONNECTION_INIT_REQ:
            DEBUG_LOG("Init TestConnection");
            RequestProcessor::SetInstance(ALLOCATE(TestConnection));
            break;
        default:
            DEBUG_LOG("Invalid Packet type, cannot initialise processor");
            return SMB_ERROR;
    }

    if (!ALLOCATED(RequestProcessor::GetInstance()))
    {
        ERROR_LOG("SessionManager::InitialiseProcessor, processor allocation failed");
        return SMB_ALLOCATION_FAILED;
    }
    RequestProcessor::GetInstance()->SetSessionManager(this);
    std::string request_id(packet->GetID());
    RequestProcessor::GetInstance()->Init(request_id);
    return SMB_SUCCESS;
}

/*!
 * Process read event on socket
 * @return
 *      SMB_SUCCESS - successful
 */
int SessionManager::ProcessReadEvent()
{
    int ret;
    INFO_LOG("Got a read event");
    Configuration &c = Configuration::GetInstance();
    while (!should_exit)
    {
        char buffer[atoi(c[C_UNIX_SOCK_BUFFER])];
        int len = 0;

        Packet *request = GetLastRequest();
        TRACE_LOG("Request %p", request);
        if (request == NULL || request->_complete)
        {
            TRACE_LOG("Allocating new request");
            /* we have a new request */
            len = _sock->Peek(buffer, HEADER_SIZE);

            if (len == SMB_AGAIN || len < 0 || len < HEADER_SIZE)
            {
                return len;
            }
            request = ALLOCATE(Packet);
            /* add header */
            memcpy(request->_header, buffer, HEADER_SIZE);
            request->_data = ALLOCATE_ARR(char, request->GetLength());
            if (!ALLOCATED(request->_data))
            {
                ERROR_LOG("SessionManager::ProcessReadEvent, memory allocation failed");
                return SMB_ALLOCATION_FAILED;
            }
            _sock->Read(buffer, HEADER_SIZE);
            PushRequest(request);
        }

        int remaining_data = request->GetLength() - request->_p_len;
        DEBUG_LOG("remaining_data %d, len from header %d, p-len %d", remaining_data, request->GetLength(),
                  request->_p_len);
        ret = _sock->Read(buffer, remaining_data > (int) sizeof(buffer) ? sizeof(buffer) : remaining_data);

        if (ret == SMB_AGAIN)
        {
            DEBUG_LOG("SessionManager::ProcessReadEvent Read fail, try again");
            break;
        }
        else if (ret == 0 || ret == SMB_EOF || ret == SMB_RESET || ret < 0)
        {
            DEBUG_LOG("SessionManager::ProcessReadEvent Read error:%d", ret);
            break;
        }

        memcpy(request->_data + request->_p_len, buffer, ret);
        request->_p_len += ret;
        DEBUG_LOG("_p_len %d", request->_p_len);

        if (request->_p_len == request->GetLength())
        {
            TRACE_LOG("SessionManager::ProcessReadEvent Got a request, signal processor, ready-packet %p", request);
            request->_complete = true;
            signal_process_request();
        }

    }

    return SMB_SUCCESS;
}

/*!
 * Process write event on socket
 * @return
 *      SMB_SUCCESS - successful
 */
int SessionManager::ProcessWriteEvent()
{
    TRACE_LOG("Got a write event");
    if (!_write_mtx.try_lock())
    {
        DEBUG_LOG("SessionManager::ProcessWriteEvent Data already being sent");
        return SMB_SUCCESS;
    }
    while (!should_exit)
    {
        int sent = 0;
        Packet *res = PopResponse();
        if (res)
        {
            DEBUG_LOG("SessionManager::ProcessWriteEvent Sending data");
            if (!res->_hdr_sent)
            {
                sent = _sock->Send(res->_header + res->_p_len, HEADER_SIZE);
                if (sent == SMB_AGAIN)
                {
                    DEBUG_LOG("SessionManager::ProcessWriteEvent SMB_AGAIN try again to send the header");
                    PushResponseAgain(res);
                    break;
                }
                else if (sent < 0)
                {
                    ERROR_LOG("SessionManager::ProcessWriteEvent write failed %s", GetError(sent));
                    FREE(res);
                    _write_mtx.unlock();
                    return SMB_ERROR;
                }
                if (sent == HEADER_SIZE)
                {
                    DEBUG_LOG("SessionManager::ProcessWriteEvent Header sent");
                    res->_hdr_sent = true;
                    res->_p_len += HEADER_SIZE;
                }
                else
                {
                    DEBUG_LOG("SessionManager::ProcessWriteEvent keep trying till whole header is sent");
                    res->_p_len += sent;
                    PushResponseAgain(res);
                    break;
                }
            }
            int data_to_sent = res->GetLength() - (res->_p_len - HEADER_SIZE);
            int start_offset = res->_p_len - HEADER_SIZE;
            DEBUG_LOG("Data offset %d, size from header %d, data_to_sent %d", start_offset, res->GetLength(),
                      data_to_sent);
            sent = _sock->Send(res->_data + start_offset, data_to_sent);
            if (sent == SMB_AGAIN)
            {
                DEBUG_LOG("SessionManager::ProcessWriteEvent SMB_AGAIN try again to send the data");
                PushResponseAgain(res);
                break;
            }
            else if (sent < 0)
            {
                ERROR_LOG("SessionManager::ProcessWriteEvent write failed %s", GetError(sent));
                FREE(res);
                _sock->Close();
                _write_mtx.unlock();
                return SMB_ERROR;
            }
            res->_p_len += sent;

            if (res->_p_len == (HEADER_SIZE + res->GetLength()))
            {
                FREE(res);
            }
            else
            {
                DEBUG_LOG("SessionManager::ProcessWriteEvent Data not completely send, add to queue again");
                PushResponseAgain(res);
                break;
            }
        }
        else
        {
            TRACE_LOG("SessionManager::ProcessWriteEvent No data available for writing");
            break;
        }
    }
    _write_mtx.unlock();
    return SMB_SUCCESS;
}

/*!
 * Cleanup, called before server is ready to serve next request
 * @return
 *      SMB_SUCCESS - successful
 *      Otherwise - error
 */
int SessionManager::CleanUp()
{
    std::lock_guard<std::mutex> lk(_reader_lock);
    FreeAllResponse();
    FreeAllRequest();
    return SMB_SUCCESS;
}

/*!
 * Quit functions, called before destruction
 * @return
 *      SMB_SUCCESS - successful
 *      Otherwise - error
 */
int SessionManager::Quit()
{
    if (_processor_thread)
    {
        _processor_thread->join();
        FREE(_processor_thread);
        _processor_thread = NULL;
    }
    FreeAllResponse();
    FreeAllRequest();
    return SMB_SUCCESS;
}

/*!
 * Push the response packet in queue at tail and tries to send it.
 * @param response - response packet
 */
void SessionManager::PushResponse(Packet *response)
{
    std::lock_guard<std::mutex> scoped_lock(_res_queue_mtx);
    _res_queue.push_back(response);
}

/*!
 * Push the response back to head of queue
 * @param res - response
 */
void SessionManager::PushResponseAgain(Packet *res)
{
    std::lock_guard<std::mutex> scoped_lock(_res_queue_mtx);
    _res_queue.push_front(res);
}

/*!
 * Pop response packet from queue
 * @return
 * Packet
 */
Packet *SessionManager::PopResponse()
{
    std::lock_guard<std::mutex> scoped_lock(_res_queue_mtx);
    if (_res_queue.empty())
    {
        TRACE_LOG("SessionManager::PopResponse Empty queue");
        return NULL;
    }
    Packet *res = _res_queue.front();
    _res_queue.pop_front();
    return res;
}

/*!
 * Check if more buffer space is available in response queue
 * @return
 */
bool SessionManager::IsResponseSpaceAvailable()
{
    DEBUG_LOG("Buffer Size %d, Response queue size %d", _buff_size, _res_queue.size());
    return _res_queue.size() < _buff_size;
}

/*!
 * Frees all elements from response queue
 */
void SessionManager::FreeAllResponse()
{
    DEBUG_LOG("SessionManager::FreeAllResponse");
    std::lock_guard<std::mutex> scoped_lock(_res_queue_mtx);
    while (!_res_queue.empty())
    {
        Packet *res = _res_queue.front();
        _res_queue.pop_front();
        FREE(res);
    }
}

/*!
 * Push request packet in request-queue at tail
 * to be picked up by ProcessRequest thread
 * @param req - request packet
 */
void SessionManager::PushRequest(Packet *req)
{
    std::lock_guard<std::mutex> scoped_lock(_req_queue_mtx);
    _req_queue.push_back(req);
}

/*!
 * Push the request back to head of queue
 * @param req - request
 */
void SessionManager::PushRequestAgain(Packet *req)
{
    std::lock_guard<std::mutex> scoped_lock(_req_queue_mtx);
    _req_queue.push_front(req);
}

/*!
 * Pop request from the queue
 * @return
 * packet
 */
Packet *SessionManager::PopRequest()
{
    std::lock_guard<std::mutex> scoped_lock(_req_queue_mtx);
    if (!_req_queue.empty())
    {
        Packet *res = _req_queue.front();
        _req_queue.pop_front();
        return res;
    }
    TRACE_LOG("SessionManager::PopRequest Empty queue");
    return NULL;

}

/*!
 * Check if more buffer space is available in request queue
 * @return
 */
bool SessionManager::IsRequestSpaceAvailable()
{
    return _req_queue.size() < _buff_size;
}

/*!
 * Get last added request from the request queue
 * @return
 * packet
 */
Packet *SessionManager::GetLastRequest()
{
    std::lock_guard<std::mutex> scoped_lock(_req_queue_mtx);
    if (!_req_queue.empty())
    {
        Packet *res = _req_queue.back();
        return res;
    }
    TRACE_LOG("SessionManager::GetLastRequest Empty queue");
    return NULL;
}

/*!
 * Frees all elements from response queue
 */
void SessionManager::FreeAllRequest()
{
    DEBUG_LOG("SessionManager::FreeAllRequest");
    std::lock_guard<std::mutex> scoped_lock(_req_queue_mtx);
    while (!_req_queue.empty())
    {
        Packet *res = _req_queue.front();
        _req_queue.pop_front();
        FREE(res);
    }
}

/*!
 * Reset idle-timeout for application
 */
void SessionManager::ResetTimer()
{
    _smbConnector->ResetTimer();
}
