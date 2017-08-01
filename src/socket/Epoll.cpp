/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#include "Epoll.h"
#include "base/Log.h"
#include "base/Error.h"


//take the fix from https://code.google.com/p/dart/source/diff?spec=svn32963&r=32963&format=side&path=/branches/bleeding_edge/dart/runtime/bin/eventhandler_android.cc
#ifndef EPOLLRDHUP
#define EPOLLRDHUP 0x2000
#endif

#define SKIP_PTR 0xffffffff

/*!
 * Constructor
 */
Epoll::Epoll()
{
    _efd = epoll_create1(0);
    _event_list = static_cast<struct epoll_event *>(calloc(MAX_SIGNALED_EVENT, sizeof(struct epoll_event)));
    if (_event_list == NULL)
    {
        ERROR_LOG("_event_list == NULL");
    }
    _event_signal = 0;
}

/*!
 * Destructor
 */
Epoll::~Epoll()
{
    close(_efd);
    free(_event_list);
}

/*!
 * Add a socket to wait for read event
 *
 * @param fd       - file descriptor of the listening socket
 * @param data_ptr - user data associated with the socket
 *
 * @return
 * SMB_SUCCESS    - Successful
 * Otherwise - Failed
 */
int Epoll::AddEvent(int fd, void *data_ptr, int event_to_listen)
{
    struct epoll_event event;

    DEBUG_LOG("Epoll::AddEvent fd=%d %s", fd, GetEventStr(event_to_listen));

    event.data.ptr = data_ptr;
    event.events = EPOLLET | EPOLLRDHUP | EPOLLPRI;

#ifdef _DEBUG_
    int numSet_bits = __builtin_popcount(event_to_listen);
    if (numSet_bits > 2)
    {
        DEBUG_LOG("Epoll::AddEvent Wrong event to listen: number of set bits=%d greater than 2", numSet_bits);
        return SMB_ERROR;
    }

    if (ffs(event_to_listen) > ffs(EVENT_HUP) || event_to_listen < 1)
    {
        DEBUG_LOG("Epoll::AddEvent Invalid event to listen: %d", event_to_listen);
        return SMB_ERROR;
    }

    if (fcntl(fd, F_GETFD) != 0)
    {
        DEBUG_LOG("Epoll::AddEvent Invalid/Unopened File Descriptor: %d", fd);
        return SMB_ERROR;
    }
#endif

    assert(fd >= 0);

    if (event_to_listen & EVENT_READ)
    {
        event.events |= EPOLLIN;
    }
    if (event_to_listen & EVENT_WRITE)
    {
        event.events |= EPOLLOUT;
    }

    int ret = epoll_ctl(_efd, EPOLL_CTL_ADD, fd, &event);

    if (ret == -1)
    {
        if (errno == EEXIST)
            INFO_LOG("epoll_ctl errno = %d (%s)", errno, strerror(errno));
        else
            ERROR_LOG("epoll_ctl errno = %d (%s)", errno, strerror(errno));

        return SMB_ERROR;
    }
    return SMB_SUCCESS;
}

/*!
 * Clear the event from event table
 *
 * @param fd             - file descriptor of the listening socket
 * @param event_to_clear - event to be cleared
 *
 * @return
 * SMB_SUCCESS    - Successful
 * Otherwise - Failed
 */
int Epoll::DeleteEvent(int fd, int event_to_clear)
{
    DEBUG_LOG("Epoll::DeleteEvent fd=%d", fd);

    int ret = epoll_ctl(_efd, EPOLL_CTL_DEL, fd, NULL);

    if (ret == -1)
    {
        if (errno == EBADF)
        {
            WARNING_LOG("Unable to delete epoll event. errno=%d fd=%d", errno, _efd);
        }
        else if (errno != ENOENT)
        {
            // Don't log if socket is not added to epoll before deleting
            ERROR_LOG("Unable to delete epoll event. errno=%d", errno);
        }
        return SMB_ERROR;
    }

    return SMB_SUCCESS;
}

/*!
 * Wait for event on all the sockets until timeout
 *
 * @param timeout - timeout in sec
 *
 * @return
 * SMB_SUCCESS    - Got an event
 * Otherwise - Timeout or error occurred
 */
int Epoll::WaitForEvent(int timeout)
{
    int timeout_msec;

    if (timeout <= 0)
    {
        timeout_msec = -1;
    }
    else
    {
        timeout_msec = timeout * 1000;
    }

    _event_signal = epoll_wait(_efd, _event_list, MAX_SIGNALED_EVENT, timeout_msec);

    if (_event_signal > 0)
    {
        DEBUG_LOG("Got socket event");
        return SMB_SUCCESS;
    }
    else if (_event_signal == 0)
    {
        return SMB_TIMEOUT;
    }
    else
    {
        // Receiving interrupted system call is normal behavior and should not trigger a warning message
        if (errno == EINTR)
        {
            TRACE_LOG("epoll_wait returns %d err=%s", _event_signal, strerror(errno));
        }
        else
        {
            ERROR_LOG("epoll_wait returns %d err=%s", _event_signal, strerror(errno));
        }
        return SMB_ERROR;
    }
}

/*!
 * Get an array of signaled events by retrieving an array of user data belonging to the signaled events
 * This function will copy the user data into an array preallocated by the caller.
 *
 * @param signaled_list - array of user data to return
 *
 * @param maxlen - max size of the array
 *
 * @return
 * Number of signal events in the returning array
 */
int Epoll::GetSignaledEvents(EVENT signaled_list[], int maxlen)
{
    int i = 0;
    int j = 0;
    int check_limit = MIN(MIN(_event_signal, maxlen), MAX_SIGNALED_EVENT);

    for (; i < check_limit; ++i)
    {
        if (_event_list[i].data.ptr != (void *) SKIP_PTR)
        {
            signaled_list[j].data = _event_list[i].data.ptr;

            signaled_list[j].type = 0;

            if (_event_list[i].events & EPOLLIN)
            {
                DEBUG_LOG("epoll received EPOLLIN event");
                signaled_list[j].type |= EVENT_READ;
            }

            if (_event_list[i].events & EPOLLOUT)
            {
                DEBUG_LOG("epoll received EPOLLOUT event");
                signaled_list[j].type |= EVENT_WRITE;
            }

            if (_event_list[i].events & EPOLLERR)
            {
                INFO_LOG("epoll received EPOLLERR event");
                signaled_list[j].type |= EVENT_ERROR;
            }
            if (_event_list[i].events & EPOLLHUP)
            {
                INFO_LOG("epoll received EPOLLHUP event");
                signaled_list[j].type |= EVENT_HUP;
            }
            if (_event_list[i].events & EPOLLRDHUP)
            {
                // peer has issue a tcp SHUT_WR
                INFO_LOG("epoll received EPOLLRDHUP event");
                signaled_list[j].type |= EVENT_RDHUP;
            }
            if (_event_list[i].events & EPOLLPRI)
            {
                INFO_LOG("epoll received EPOLLPRI event");
                signaled_list[j].type |= EVENT_READ;
            }
            j++;
        }
    }

    return j;
}
