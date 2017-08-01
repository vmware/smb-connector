/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#ifdef _DEBUG_

#include <gtest/gtest.h>
#include "base/Error.h"
#include "base/Protocol.h"
#include "processor/TestConnection.h"
#include "core/Server.h"

extern std::string test_url;
extern std::string test_un;
extern std::string test_pass;
extern std::string test_wg;
extern std::string test_share;

extern std::string request_id;
extern UnixDomainSocket sock;

static TestConnection *processor = NULL;
static Server *server = NULL;

TEST(TestConnection, Init)
{
    should_exit = 1;
    server = ALLOCATE(Server);
    processor = ALLOCATE(TestConnection);
    RequestProcessor::SetInstance(processor);
    processor->SetSessionManager(server->GetSessionManager());
    processor->SetUrl(test_url+"/"+test_share);
    processor->SetWorkGroup(test_wg);
    processor->SetUserName(test_un);
    processor->SetPassword(test_pass);
    EXPECT_EQ(SMB_SUCCESS, processor->Init(request_id));
}

TEST(TestConnection, wrong_password)
{
    /*wrong password */
    processor->SetPassword("123456");
    Packet *packet = ALLOCATE(Packet);
    EXPECT_EQ(SMB_SUCCESS, processor->PacketCreator()->CreatePacket(packet, TEST_CONNECTION_INIT_REQ, NULL));
    EXPECT_EQ(SMB_ERROR, processor->ProcessRequest(packet));
    processor->SetPassword(test_pass);
    packet->Reset();
    FREE(packet);
}

TEST(TestConnection, wrong_username)
{
    /*wrong username*/
    processor->SetUserName("testun");
    Packet *packet = ALLOCATE(Packet);
    EXPECT_EQ(SMB_SUCCESS, processor->PacketCreator()->CreatePacket(packet, TEST_CONNECTION_INIT_REQ, NULL));
    EXPECT_EQ(SMB_ERROR, processor->ProcessRequest(packet));
    processor->SetUserName(test_un);
    packet->Reset();
    FREE(packet);
}

TEST(TestConnection, wrong_url)
{
    /*wrong url*/
    processor->SetUrl("test_url.com/share/folder");
    Packet *packet = ALLOCATE(Packet);
    EXPECT_EQ(SMB_SUCCESS, processor->PacketCreator()->CreatePacket(packet, TEST_CONNECTION_INIT_REQ, NULL));
    EXPECT_EQ(SMB_ERROR, processor->ProcessRequest(packet));
    processor->SetUrl(test_url+"/"+test_share);
    packet->Reset();
    FREE(packet);
}

TEST(TestConnection, success)
{
    std::string tmp = "2345";
    Packet *packet = ALLOCATE(Packet);
    EXPECT_EQ(SMB_SUCCESS, processor->PacketCreator()->CreatePacket(packet, TEST_CONNECTION_INIT_REQ, NULL));
    processor->SetRequestId(tmp);
    EXPECT_EQ(SMB_ERROR, processor->ProcessRequest(packet));
    processor->SetRequestId(request_id);
    packet->Reset();
    FREE(packet);
    packet = ALLOCATE(Packet);
    EXPECT_EQ(SMB_SUCCESS, processor->PacketCreator()->CreatePacket(packet, TEST_CONNECTION_INIT_REQ, NULL));
    EXPECT_EQ(SMB_SUCCESS, processor->ProcessRequest(packet));
    packet->Reset();
    FREE(packet);
}

TEST(TestConnection, resp)
{
    Packet *packet = ALLOCATE(Packet);
    bool isDirectory = true;
    EXPECT_EQ(SMB_SUCCESS, processor->PacketCreator()->CreatePacket(packet, TEST_CONNECTION_INIT_RESP, &isDirectory));
    EXPECT_EQ(SMB_SUCCESS, processor->ProcessRequest(packet));
    packet->Reset();
    FREE(packet);
}

TEST(TestConnection, error)
{
    Packet *packet = ALLOCATE(Packet);
    EXPECT_EQ(SMB_SUCCESS, processor->PacketCreator()->CreateStatusPacket(packet, TEST_CONNECTION_ERROR_RESP, 17, true));
    EXPECT_EQ(SMB_SUCCESS, processor->ProcessRequest(packet));
    packet->Reset();
    FREE(packet);
    packet = ALLOCATE(Packet);
    EXPECT_EQ(SMB_SUCCESS, processor->PacketCreator()->CreateStatusPacket(packet, TEST_CONNECTION_ERROR_RESP, SMB_ERROR, false));
    EXPECT_EQ(SMB_SUCCESS, processor->ProcessRequest(packet));
    packet->Reset();
    FREE(packet);
}

TEST(TestConnection, Quit)
{
    should_exit = 1;
    processor->Quit();
    FREE(processor);
    FREE(server);
    processor = NULL;
}

#endif