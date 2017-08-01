/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#include "Server.h"
#include "base/Error.h"
#include "base/Log.h"
#include "processor/RequestProcessor.h"

extern int should_exit;

/*!
 * Constructor
 */
Server::Server()
{
    _listen_sock = NULL;
    _client_sock = NULL;
    memset(_event_list, 0, sizeof(_event_list));
}

/*!
 * Destructor
 */
Server::~Server()
{
    //Empty Destructor
}

/*!
 * Checks if app has been idle for more
 * than idle timeout
 * @return
 * true - if idle-timeout is expired
 * false - if idle-timeout is not expired
 */
bool Server::timer_expired()
{
    Configuration &c = Configuration::GetInstance();
    return (_end.tv_sec - _start.tv_sec) >= atoi(c[C_IDLE_TIMEOUT]);
}

/*!
 * Initialise Server
 * @param path - unix-domain sock path
 * @return
 * SMB_SUCCESS - successful
 * Otherwise - failure
 */
int Server::Init(const char *path, int op_code)
{
    DEBUG_LOG("Server::Init");
    clock_gettime(CLOCK_REALTIME, &_start);
    _listen_sock = ALLOCATE(UnixDomainSocket, path);
    if (!ALLOCATED(_listen_sock))
    {
        ERROR_LOG("Server::Init _listen_sock allocation failed");
        return SMB_ERROR;
    }
    _listen_sock->Create();
    _listen_sock->InitListening();
    _listen_sock->SetNonBlocking(true);
    _epoll.AddEvent(_listen_sock->GetFD(), NULL, EVENT_READ | EVENT_HUP);
    should_exit = 0;
    return SMB_SUCCESS;
}

/*!
 * Accepts 1 socket
 * Perform read/write on client socket
 */
void Server::Runloop()
{
    int ret;
    //wait for session-manager thread to be ready
    while (!_sessionManager.IsReady())
    {
        sleep(1);
    }
    while (!should_exit)
    {
        /*
         * Wait for event for 1 second
         */
        ret = _epoll.WaitForEvent(1);

        /* check if idle-timeout is expired */
        clock_gettime(CLOCK_REALTIME, &_end);
        if (timer_expired())
        {
            DEBUG_LOG("Server::Runloop Idle timeout expired, going down");
            should_exit = 1;
            return;
        }

        if (ret == SMB_SUCCESS)
        {
            clock_gettime(CLOCK_REALTIME, &_start);
            int event_count = _epoll.GetSignaledEvents(_event_list, MAX_SIGNALED_EVENT);

            for (int i = 0; i < event_count; ++i)
            {
                /* Accept Socket */
                if (_event_list[i].data == NULL)
                {
                    if (_event_list[i].type & EVENT_ERROR)
                    {
                        ERROR_LOG("Socket error");
                        assert(false);
                    }

                    if (_client_sock == NULL)
                    {
                        INFO_LOG("Got a connection");
                        if (_listen_sock->Accept(_client_sock) != SMB_SUCCESS)
                        {
                            DEBUG_LOG("Accept failed");
                        }
                        else
                        {
                            INFO_LOG("Socket connected");
                            _sessionManager.Init(this);
                            _epoll.AddEvent(_client_sock->GetFD(), _client_sock, EVENT_READ | EVENT_WRITE);
                        }
                    }
                    else
                    {
                        UnixDomainSocket *tmp = NULL;
                        _listen_sock->Accept(tmp);
                        tmp->Close();
                        FREE(tmp);
                        DEBUG_LOG("Already serving one client, Accept another client and close immediately");
                    }
                }
                else /* Client Socket */
                {
                    if (_event_list[i].type & EVENT_ERROR
                        || _event_list[i].type & EVENT_RDHUP
                        || _event_list[i].type & EVENT_HUP)
                    {
                        INFO_LOG("Socket closed");
                        CleanUp();
                        break;
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
        }
        else
        {
            TRACE_LOG("Epoll event timed out");
        }
    }
}

/*!
 * Cleans up resource once a request is served
 * @return
 * SMB_SUCCESS - if successful
 * Otherwise - failure
 */
int Server::CleanUp()
{
    DEBUG_LOG("Server::Cleanup");
    _sessionManager.CleanUp();
    if (_client_sock != NULL)
    {
        _epoll.DeleteEvent(_client_sock->GetFD(), EVENT_READ | EVENT_WRITE);
        _client_sock->Close();
        FREE(_client_sock);
        _client_sock = NULL;
    }

    if (RequestProcessor::GetInstance() != NULL)
    {
        RequestProcessor::GetInstance()->Quit();
        FREE(RequestProcessor::GetInstance());
        RequestProcessor::SetInstance(NULL);
    }
    return SMB_SUCCESS;
}

/*!
 * Free up resources when application is going down
 * @return
 * SMB_SUCCESS - if successful
 * Otherwise - failure
 */
int Server::Quit()
{
    DEBUG_LOG("Server::Quit");
    should_exit = 1;
    shutdown(_listen_sock->GetFD(),
             SHUT_RDWR); // shutdown listen socket so that we can fire up an event and RunLoop may exit
    _listen_sock->Close();
    FREE(_listen_sock);
    _sessionManager.Quit();
    CleanUp();
    return SMB_SUCCESS;
}
