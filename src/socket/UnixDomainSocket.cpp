/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#include <errno.h>
#include <netdb.h>

#include "base/Configuration.h"
#include "base/Error.h"
#include "base/Log.h"

#include "UnixDomainSocket.h"

/*!
 * Constructor
 */
UnixDomainSocket::UnixDomainSocket(const char *sun_path)
    : non_blocking(true), is_bound(false)
{
    //Reset the sockaddr_un structure
    fd = -1;
    memset(&local_addr, 0, sizeof(struct sockaddr_un));
    local_addr.sun_family = AF_UNIX;
    peer_addr.sun_family = AF_UNIX;
    if (sun_path == NULL)
    {
        DEBUG_LOG("UDS: No sun_path");
        return;
    }

    DEBUG_LOG("UDS: sun_path: %s", sun_path);
    strncpy(local_addr.sun_path, sun_path, sizeof(local_addr.sun_path) - 1);
}

UnixDomainSocket::UnixDomainSocket()
    : UnixDomainSocket(static_cast<const char *> (NULL))
{
    //Do nothing
}

/*!
 * Destructor
 */
UnixDomainSocket::~UnixDomainSocket()
{
    if (fd != -1)
    {
        close(fd);
    }
    fd = -1;
}

void UnixDomainSocket::SetNonBlocking(bool value)
{
    non_blocking = value;
    int ret = -1;

    if (value)
    {
        ret = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
    }
    else
    {
        ret = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK);
    }

    if (ret == -1)
    {
        ERROR_LOG("fcntl");
    }

}

/*!
 * Initialize the socket for listen and accept incoming connection
 *
 * @param port - port to listen to
 *
 * @return
 *   SMB_SUCCESS    - Successful
 *   Otherwise - Failed
 */
int UnixDomainSocket::InitListening()
{

    if (fd == -1)
    {
        ERROR_LOG("UDS: Socket is not open yet");
        return SMB_ERROR;
    }

    SetNonBlocking(true);

    // Delete the file at the path if it exists. The bind() call will create
    // a socket file at the path
    if (::unlink(local_addr.sun_path) != 0)
    {
        DEBUG_LOG("UDS: can't unlink() socket file:%s; %s",
                  local_addr.sun_path, strerror(errno));
    }

    if (Bind() != SMB_SUCCESS)
    {
        ERROR_LOG("UDS: InitListening: ERROR - Bind() returns error");
        return SMB_ERROR;
    }

    if (listen(fd, atoi(Configuration::GetInstance()[C_ACCEPT_QUEUE_SIZE])) == -1)
    {
        ERROR_LOG("UDS::ERROR - listen returns -1 errno=%d (%s)", errno, strerror(errno));
        return SMB_ERROR;
    }

    INFO_LOG("UDS::TCP server ready. Listening");

    return SMB_SUCCESS;
}

/*!
 * Precreate a TCP socket
 *
 * @param ipv6 - Use IPv6 protool (True) or IPv4 (False)
 *
 * @return
 *   SMB_SUCCESS    - Successful
 *   Otherwise - Failed
 */
int UnixDomainSocket::Create()
{
    if (fd != -1)
    {
        ERROR_LOG("UDS::Create fd != -1");
        return SMB_ERROR;
    }

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == -1)
    {
        ERROR_LOG("UDS:: cannot allocate file descriptor");
        return SMB_ERROR;
    }

    return SMB_SUCCESS;
}

/*!
 * Connect the socket to a ip:port address
 *
 * @param sa - Pointer to Unix sockaddr structure
 *
 * @return
 *   SMB_SUCCESS    - Successful
 *   Otherwise - Failed
 */
int UnixDomainSocket::Connect()
{
    int err = 0;

    //Check the fd
    if (fd == -1)
    {
        fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd == -1)
        {
            ERROR_LOG("UDS:: cannot allocate file descriptor");
            return SMB_ERROR;
        }
    }

    err = ::connect(fd, reinterpret_cast<struct sockaddr *>(&peer_addr), sizeof(peer_addr));
    if (err < 0)
    {
        err = errno;
        if (err == EINPROGRESS)
        {
            INFO_LOG("UDS::Connect returns -1 errno=%d (%s)", errno, strerror(errno));
        }
        else
        {
            ERROR_LOG("UDS::Connect returns -1 errno=%d (%s)", errno, strerror(errno));
            return SMB_ERROR;
        }
    }

    return SMB_SUCCESS;
}

/*!
 * Connect the socket to destination using sockaddr_in
 *
 * @param sun_path - Unix file path
 *
 * @return
 *   SMB_SUCCESS    - Successful
 *   Otherwise - Failed
 */
int UnixDomainSocket::Connect(const char *sun_path)
{
    if (sun_path == NULL)
    {
        ERROR_LOG("UDS: Invalid argument");
        return SMB_ERROR;
    }
    strncpy(peer_addr.sun_path, sun_path, sizeof(peer_addr.sun_path));
    return Connect();
}

/*!
 * Accept new connection from listening socket
 *
 * @param unix_socket - receiving newly created UnixStreamSocket pointer if return value is SMB_SUCCESS
 *
 * @return
 *   SMB_SUCCESS        - Successful
 *   SMB_AGAIN     - Not enough file descriptors. Caller should go back to wait.
 *   VPN_NOT_FOUND - All events processed
 *   Otherwise     - Failed
 */
int UnixDomainSocket::Accept(UnixDomainSocket *&unix_socket)
{
    int s = accept(fd, NULL, NULL);
    if (s < 0)
    {
        if (errno == EAGAIN)
        {
            return SMB_NOT_FOUND;
        }
        else if (errno == EMFILE || errno == ENFILE)
        {
            ERROR_LOG("UDS::Accept returns %d peer errno=%d [%s]. Consider increasing file descriptors limit", s,
                      errno, strerror(errno));
            return SMB_AGAIN;
        }
        else
        {
            ERROR_LOG("UDS::Accept returns %d peer errno=%d [%s]", s, errno, strerror(errno));
            return SMB_ERROR;
        }
    }
    else if (s == 0)
    {
        ERROR_LOG("UDS::Accept returns 0");
        return SMB_ERROR;
    }

    INFO_LOG("UDS::ACCEPT fd=%d", s);

    unix_socket = new UnixDomainSocket();

    unix_socket->SetFD(s);
    unix_socket->SetNonBlocking(non_blocking);

    return SMB_SUCCESS;
}

int UnixDomainSocket::Bind()
{
    // If socket is already bound, no need to bind again
    if (is_bound)
    {
        INFO_LOG("Socket: Bind: socket already bound. No need to bind again");
        return SMB_SUCCESS;
    }

    if (::bind(fd, reinterpret_cast<struct sockaddr *>(&local_addr), sizeof(local_addr)) == -1)
    {
        ERROR_LOG("Socket::ERROR - bind returns -1 errno=%d (%s)", errno, strerror(errno));
        return SMB_ERROR;
    }

    is_bound = true;

    return SMB_SUCCESS;
}

int UnixDomainSocket::Read(char *buffer, int maxlen)
{
    long ret = recv(fd, buffer, maxlen, 0);

    if (ret < 0)
    {
        if (errno == EAGAIN || errno == EINPROGRESS)
        {
            DEBUG_LOG("Read errno=%d (%s)", errno, strerror(errno));
            return SMB_AGAIN;
        }
        else
        {
            if (errno == ECONNRESET || errno == ETIMEDOUT)
            {
                INFO_LOG("Read returns %ld, errno=%d (%s)", ret, errno, strerror(errno));
                return SMB_RESET;
            }
            else
            {
                ERROR_LOG("Read returns %ld, errno=%d (%s)", ret, errno, strerror(errno));
                return SMB_ERROR;
            }
        }
    }
    else if (ret == 0)
    {
        DEBUG_LOG("Read ret==0");
        return SMB_EOF;
    }

    INFO_LOG("Received %ld bytes", ret);
    return static_cast<int>(ret);
}

int UnixDomainSocket::Send(const char *buffer, int len)
{
    long ret = send(fd, buffer, len, 0);

    if (ret < 0)
    {
        if (errno == EAGAIN || errno == EINPROGRESS)
        {
            DEBUG_LOG("Send returns %ld, errno=%d (%s)", ret, errno, strerror(errno));
            return SMB_AGAIN;
        }
        else if (errno == EPIPE)
        {
            return SMB_EOF;
        }
        else if (errno == ECONNRESET || errno == ETIMEDOUT || errno == ECONNREFUSED)
        {
            WARNING_LOG("Send returns %ld, errno=%d (%s)", ret, errno, strerror(errno));
            return SMB_RESET;
        }
        else
        {
            ERROR_LOG("Send returns %ld, errno=%d (%s)", ret, errno, strerror(errno));
            return SMB_ERROR;
        }
    }

    INFO_LOG("UnixDomainSocket %ld bytes sent", ret);
    return static_cast<int>(ret);
}

int UnixDomainSocket::Peek(char *buffer, int maxlen)
{
    long ret = recv(fd, buffer, maxlen, MSG_PEEK);

    if (ret < 0)
    {
        if (errno == EAGAIN || errno == EINPROGRESS)
        {
            DEBUG_LOG("Read errno=%d (%s)", errno, strerror(errno));
            return SMB_AGAIN;
        }
        else
        {
            if (errno == ECONNRESET || errno == ETIMEDOUT)
            {
                INFO_LOG("peek recv returns %ld, errno=%d (%s)", ret, errno, strerror(errno));
                return SMB_RESET;
            }
            else
            {
                WARNING_LOG("peek recv returns %ld, errno=%d (%s)", ret, errno, strerror(errno));
                return SMB_ERROR;
            }
        }
    }
    else if (ret == 0)
    {
        return SMB_EOF;
    }

    return static_cast<int>(ret);
}

int UnixDomainSocket::Close()
{
    DEBUG_LOG("CLOSE fd=%d", fd);

    close(fd);
    fd = -1;

    if (is_bound && ::unlink(local_addr.sun_path) != 0)
    {
        DEBUG_LOG("UDS: can't unlink() socket file:%s; %s",
                  local_addr.sun_path, strerror(errno));
    }

    return SMB_SUCCESS;
}
