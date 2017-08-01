/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#include "packet/OpenDirPacketCreator.h"
#include "base/Configuration.h"
#include "Client.h"
#include "base/Error.h"
#include "base/Protocol.h"
#include "base/Log.h"
#include "processor/DownloadProcessor.h"
#include "processor/UploadProcessor.h"
#include "processor/AddFolderProcessor.h"
#include "processor/DeleteProcessor.h"
#include "processor/TestConnection.h"

#define MAX_LEN 1000

#define GET_STR     1
#define DOWNLOAD    2
#define UPLOAD      3
#define ADD_FOLDER  4
#define DEL         5
#define LIST_SHARE  6


/*!
 * Constructor
 */
Client::Client()
    : _sock(NULL), _sun_path("")
{
    memset(_event_list, 0, sizeof(_event_list));
}

/*!
 * Destructor
 */
Client::~Client()
{
    //Destructor
}

/*!
 * Initialisation
 *
 * @param path     - unix-domain socket path
 * @param op_code  - Operation to be performed
 *
 * @return
 * SMB_SUCCESS    - Successful
 * Otherwise - Failed
 */
int Client::Init(const char *path, int op_code)
{
    Configuration &c = Configuration::GetInstance();
    should_exit = 0;
    switch (op_code)
    {
        case GET_STR:
            RequestProcessor::SetInstance(new OpenDirReqProcessor);
            static_cast<OpenDirReqProcessor *>(RequestProcessor::GetInstance())->SetPageSize(atoi(c[C_PAGE_SIZE]));
            static_cast<OpenDirReqProcessor *>(RequestProcessor::GetInstance())->SetShowHiddenFiles(
                atoi(c[C_SHOW_HIDDEN_FILES]));
            static_cast<OpenDirReqProcessor *>(RequestProcessor::GetInstance())->SetShowOnlyFolders(
                atoi(c[C_SHOW_ONLY_FOLDERS]));
            break;
        case DOWNLOAD:
            RequestProcessor::SetInstance(new DownloadProcessor);
            break;
        case UPLOAD:
            RequestProcessor::SetInstance(new UploadProcessor);
            break;
        case ADD_FOLDER:
            RequestProcessor::SetInstance(new AddFolderProcessor);
            break;
        case DEL:
            RequestProcessor::SetInstance(new DeleteProcessor);
            break;
        case LIST_SHARE:
            RequestProcessor::SetInstance(new TestConnection);
            break;
        default:
            ERROR_LOG("Invalid operation");
            exit(1);
    }

    RequestProcessor::GetInstance()->SetUrl(c[C_URL]);
    RequestProcessor::GetInstance()->SetWorkGroup(c[C_WORK_GROUP]);
    RequestProcessor::GetInstance()->SetUserName(c[C_USER_NAME]);
    RequestProcessor::GetInstance()->SetPassword(c[C_PASSWORD]);
    RequestProcessor::GetInstance()->SetSessionManager(&_sessionManager);
    _sock = new UnixDomainSocket();
    _sun_path = path;
    _sock->Create();
    _sock->SetNonBlocking(true);
    Packet *req = ALLOCATE(Packet);
    std::string request_id("1234");
    RequestProcessor::GetInstance()->Init(request_id);

    switch (op_code)
    {
        case GET_STR:
            RequestProcessor::GetInstance()->PacketCreator()->CreatePacket(req, GET_STRUCTURE_INIT_REQ, NULL);
            break;
        case DOWNLOAD:
        {
            DownloadProcessor *processor = dynamic_cast<DownloadProcessor *>(RequestProcessor::GetInstance());
            if (processor == NULL)
            {
                ERROR_LOG("Client::Init dynamic_cast<DownloadProcessor> failed");
                return SMB_ERROR;
            }
            processor->OpenFile();
            processor->SetStartOffset(atoi(c[C_START_OFFSET]));
            processor->SetEndOffset(atoi(c[C_END_OFFSET]));
            processor->PacketCreator()->CreatePacket(req, DOWNLOAD_INIT_REQ, NULL);
        }
            break;
        case UPLOAD:
        {
            UploadProcessor *processor = dynamic_cast<UploadProcessor *>(RequestProcessor::GetInstance());
            if (processor == NULL)
            {
                ERROR_LOG("Client::Init dynamic_cast<UploadProcessor> failed");
                return SMB_ERROR;
            }
            processor->OpenFile();
            processor->PacketCreator()->CreatePacket(req, UPLOAD_INIT_REQ, NULL);
        }
            break;
        case ADD_FOLDER:
            RequestProcessor::GetInstance()->PacketCreator()->CreatePacket(req, ADD_FOLDER_INIT_REQ, NULL);
            break;
        case DEL:
            RequestProcessor::GetInstance()->PacketCreator()->CreatePacket(req, DELETE_INIT_REQ, NULL);
            break;
        case LIST_SHARE:
            RequestProcessor::GetInstance()->PacketCreator()->CreatePacket(req, TEST_CONNECTION_INIT_REQ, NULL);
            break;
        default:
            return SMB_ERROR;
    }
    _sessionManager.Init(this);
    _sessionManager.PushResponseAgain(req);
    return SMB_SUCCESS;
}

/*!
 * Runloop
 * Handles event for unix-domain socket in a separate thread
 */
void Client::Runloop()
{
    //wait for session-manager thread to start
    while (!_sessionManager.IsReady())
    {
        sleep(1);
    }

    if (_sock->Connect(_sun_path.c_str()) == SMB_ERROR)
    {
        should_exit = 1;
        return;
    }
    _epoll.AddEvent(_sock->GetFD(), _sock, EVENT_READ | EVENT_WRITE);

    int ret;

    while (!should_exit)
    {
        ret = _epoll.WaitForEvent(1);
        if (ret == SMB_SUCCESS)
        {
            int event_count = _epoll.GetSignaledEvents(_event_list, MAX_SIGNALED_EVENT);

            for (int i = 0; i < event_count; ++i)
            {
                if (_event_list[i].type & EVENT_ERROR
                    || _event_list[i].type & EVENT_RDHUP
                    || _event_list[i].type & EVENT_HUP)
                {
                    INFO_LOG("Socket closed");
                    should_exit = 1;
                }
                if (_event_list[i].type & EVENT_READ)
                {
                    _sessionManager.ProcessReadEvent();
                }
                if (_event_list[i].type & EVENT_WRITE)
                {
                    _sessionManager.ProcessWriteEvent();
                }
            }
        }
        else if (ret == SMB_TIMEOUT)
        {
            TRACE_LOG("Timed out");
        }
    }
}

/*!
 * Cleanup
 * @return
 */
int Client::CleanUp()
{
    return Quit();
}

/*!
 * Quit
 */
int Client::Quit()
{
    DEBUG_LOG("Client::Quit");
    should_exit = 1;
    FREE(_sock);
    _sock = NULL;
    _sessionManager.Quit();
    if (RequestProcessor::GetInstance() != NULL)
    {
        RequestProcessor::GetInstance()->Quit();
        FREE(RequestProcessor::GetInstance());
        RequestProcessor::SetInstance(NULL);
    }
    return SMB_SUCCESS;
}
