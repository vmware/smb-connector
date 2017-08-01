/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */


#ifndef EPOLL_H_
#define EPOLL_H_

#include <sys/epoll.h>
#include <string.h>

/*!
 * EPoll provides the interface to Linux epoll event notification
 */

typedef struct socket_event_t
{
    void *data;
    int type;
} EVENT;

#define MAX_SIGNALED_EVENT 256

#define EVENT_READ         0x0001
#define EVENT_WRITE        0x0002
#define EVENT_ERROR        0x0004
#define EVENT_RDHUP        0x0008
#define EVENT_HUP          0x0010

/*!
 * Get a string representation of the event
 *
 * @param event - Event to be converted to string
 *
 * @return
 *   a constant string buffer containing the representation
 */
inline const char *GetEventStr(int event)
{
    switch (event)
    {
        case EVENT_READ               :
            return "EVENT_READ";
        case EVENT_WRITE              :
            return "EVENT_WRITE";
        case EVENT_READ | EVENT_WRITE :
            return "EVENT_READ | EVENT_WRITE";
        default                       :
            return "OTHER";
    }
}

class Epoll
{
private:
    int _efd;
    struct epoll_event *_event_list;
    int _event_signal;

public:
    Epoll();
    virtual ~Epoll();

    virtual int AddEvent(int fd, void *data_ptr, int event_to_listen);
    virtual int DeleteEvent(int fd, int event_to_delete);
    virtual int WaitForEvent(int timeout);
    virtual int GetSignaledEvents(EVENT signaled_list[], int maxlen);
};

#endif /* EPOLL_H_ */
