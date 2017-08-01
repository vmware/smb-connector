/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#ifdef _DEBUG_
#include <gtest/gtest.h>
#include "base/Error.h"
#include "socket/UnixDomainSocket.h"

TEST(UnixDomainSocket, Create)
{
    UnixDomainSocket s_socket("sample");
    EXPECT_EQ(SMB_SUCCESS, s_socket.Create());
    EXPECT_TRUE(s_socket.GetFD() > 0);
    EXPECT_EQ(SMB_ERROR, s_socket.Create());

    UnixDomainSocket c_socket;
    EXPECT_EQ(SMB_SUCCESS, c_socket.Create());
    EXPECT_TRUE(s_socket.GetFD() > 0);
    EXPECT_EQ(SMB_ERROR, c_socket.Create());
}

TEST(UnixDomainSocket, Listen_Connect_Accept)
{
    UnixDomainSocket s_socket("sample");
    UnixDomainSocket c_socket("sample");

    EXPECT_EQ(SMB_ERROR, s_socket.InitListening());
    EXPECT_EQ(SMB_SUCCESS, s_socket.Create());
    EXPECT_EQ(SMB_SUCCESS, s_socket.InitListening());
    EXPECT_TRUE(s_socket.GetFD() > 0);

    EXPECT_EQ(SMB_ERROR, c_socket.Connect());
    EXPECT_EQ(SMB_SUCCESS, c_socket.Connect("sample"));

    UnixDomainSocket *sock = NULL;
    EXPECT_EQ(SMB_SUCCESS, s_socket.Accept(sock));
    EXPECT_TRUE(sock != NULL);
    delete sock;
}

TEST(UnixDomainSocket, Read_Write)
{
    UnixDomainSocket s_socket("sample");
    UnixDomainSocket c_socket("sample");

    EXPECT_EQ(SMB_SUCCESS, s_socket.Create());
    EXPECT_EQ(SMB_SUCCESS, s_socket.InitListening());
    EXPECT_TRUE(s_socket.GetFD() > 0);

    EXPECT_EQ(SMB_ERROR, c_socket.Connect());
    EXPECT_EQ(SMB_SUCCESS, c_socket.Connect("sample"));

    UnixDomainSocket *sock = NULL;
    EXPECT_EQ(SMB_SUCCESS, s_socket.Accept(sock));
    EXPECT_TRUE(sock != NULL);

    c_socket.SetNonBlocking(false);
    sock->SetNonBlocking(false);

    EXPECT_EQ(5, c_socket.Send("test", 5));
    char buffer[5];
    EXPECT_EQ(5, sock->Peek(buffer, 5));
    EXPECT_EQ(strcmp(buffer, "test"), 0);
    EXPECT_EQ(5, sock->Read(buffer, 5));
    EXPECT_EQ(strcmp(buffer, "test"), 0);

    EXPECT_EQ(SMB_SUCCESS, c_socket.Close());
    EXPECT_EQ(SMB_ERROR, c_socket.Send("test", 5));
    EXPECT_EQ(SMB_EOF, sock->Read(buffer, 5));

    EXPECT_EQ(SMB_SUCCESS, sock->Close());

    delete sock;
    EXPECT_EQ(SMB_SUCCESS, s_socket.Close());
}

#endif //_DEBUG_