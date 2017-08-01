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
#include "processor/OpenDirReqProcessor.h"
#include "core/Server.h"

extern std::string test_url;
extern std::string test_un;
extern std::string test_pass;
extern std::string test_wg;
extern std::string test_share;

extern std::string request_id;
extern UnixDomainSocket sock;

static OpenDirReqProcessor *processor = NULL;
static Server *server = NULL;

TEST(OpenDirReqProcessor, Init)
{
    should_exit = 1;
    server = ALLOCATE(Server);
    processor = ALLOCATE(OpenDirReqProcessor);
    RequestProcessor::SetInstance(processor);
    processor->SetSessionManager(server->GetSessionManager());
    processor->SetUrl(test_url+"/"+test_share);
    processor->SetWorkGroup(test_wg);
    processor->SetUserName(test_un);
    processor->SetPassword(test_pass);
    processor->SetPageSize(5);
    EXPECT_EQ(SMB_SUCCESS, processor->Init(request_id));
}

TEST(OpenDirReqProcessor, wrong_password)
{
    /*wrong password */
    processor->SetPassword("123456");
    Packet *packet = ALLOCATE(Packet);
    EXPECT_EQ(SMB_SUCCESS, processor->PacketCreator()->CreatePacket(packet, GET_STRUCTURE_INIT_REQ, NULL));
    EXPECT_EQ(SMB_ERROR, processor->ProcessRequest(packet));
    processor->SetPassword(test_pass);
    packet->Reset();
    FREE(packet);
}

TEST(OpenDirReqProcessor, wrong_username)
{
    /*wrong username*/
    processor->SetUserName("testun");
    Packet *packet = ALLOCATE(Packet);
    EXPECT_EQ(SMB_SUCCESS, processor->PacketCreator()->CreatePacket(packet, GET_STRUCTURE_INIT_REQ, NULL));
    EXPECT_EQ(SMB_ERROR, processor->ProcessRequest(packet));
    processor->SetUserName(test_un);
    packet->Reset();
    FREE(packet);
}

TEST(OpenDirReqProcessor, wrong_url)
{
    /*wrong url*/
    processor->SetUrl("test_url.com/share/folder");
    Packet *packet = ALLOCATE(Packet);
    EXPECT_EQ(SMB_SUCCESS, processor->PacketCreator()->CreatePacket(packet, GET_STRUCTURE_INIT_REQ, NULL));
    EXPECT_EQ(SMB_ERROR, processor->ProcessRequest(packet));
    processor->SetUrl(test_url+"/"+test_share);
    packet->Reset();
    FREE(packet);
}

TEST(OpenDirReqProcessor, success)
{
    std::string tmp = "2345";
    Packet *packet = ALLOCATE(Packet);
    EXPECT_EQ(SMB_SUCCESS, processor->PacketCreator()->CreatePacket(packet, GET_STRUCTURE_INIT_REQ, NULL));
    processor->SetRequestId(tmp);
    EXPECT_EQ(SMB_ERROR, processor->ProcessRequest(packet));
    processor->SetRequestId(request_id);
    packet->Reset();
    FREE(packet);
    packet = ALLOCATE(Packet);
    EXPECT_EQ(SMB_SUCCESS, processor->PacketCreator()->CreatePacket(packet, GET_STRUCTURE_INIT_REQ, NULL));
    EXPECT_EQ(SMB_SUCCESS, processor->ProcessRequest(packet));
    packet->Reset();
    FREE(packet);

    packet = server->GetSessionManager()->PopResponse();
    while(packet)
    {
        processor->ProcessRequest(packet);
        FREE(packet);
        packet = server->GetSessionManager()->PopResponse();
    }
}

TEST(OpenDirReqProcessor, error)
{
    Packet *packet = ALLOCATE(Packet);
    EXPECT_EQ(SMB_SUCCESS, processor->PacketCreator()->CreateStatusPacket(packet, GET_STRUCTURE_ERROR_RESP, 17, true));
    EXPECT_EQ(SMB_SUCCESS, processor->ProcessRequest(packet));
    packet->Reset();
    FREE(packet);
    packet = ALLOCATE(Packet);
    EXPECT_EQ(SMB_SUCCESS, processor->PacketCreator()->CreateStatusPacket(packet, GET_STRUCTURE_ERROR_RESP, SMB_ERROR, false));
    EXPECT_EQ(SMB_SUCCESS, processor->ProcessRequest(packet));
    packet->Reset();
    FREE(packet);
}

TEST(OpenDirReqProcessor, Quit)
{
    should_exit = 1;
    processor->Quit();
    FREE(processor);
    FREE(server);
    processor = NULL;
}

#endif