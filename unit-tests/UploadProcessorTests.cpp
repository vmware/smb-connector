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
#include "processor/UploadProcessor.h"
#include "core/Server.h"

extern std::string test_url;
extern std::string test_un;
extern std::string test_pass;
extern std::string test_wg;
extern std::string test_share;

extern std::string request_id;
extern UnixDomainSocket sock;

static UploadProcessor *processor = NULL;
static std::string file="twrp.img";
static Server *server = NULL;

TEST(UploadProcessor, Init)
{
    should_exit = 1;
    server = ALLOCATE(Server);
    Configuration &c = Configuration::GetInstance();
    c.Set(C_BUFFER_SIZE, "1000");
    server->GetSessionManager()->Init(server);
    processor = ALLOCATE(UploadProcessor);
    RequestProcessor::SetInstance(processor);
    processor->SetSessionManager(server->GetSessionManager());
    processor->SetUrl(test_url+"/"+test_share+"/"+file);
    processor->SetWorkGroup(test_wg);
    processor->SetUserName(test_un);
    processor->SetPassword(test_pass);
    EXPECT_EQ(SMB_SUCCESS, processor->Init(request_id));
}

TEST(UploadProcessor, wrong_password)
{
    /*wrong password */
    processor->SetPassword("123456");
    Packet *packet = ALLOCATE(Packet);
    EXPECT_EQ(SMB_SUCCESS, processor->PacketCreator()->CreatePacket(packet, UPLOAD_INIT_REQ, NULL));
    EXPECT_EQ(SMB_ERROR, processor->ProcessRequest(packet));
    processor->SetPassword(test_pass);
    packet->Reset();
    FREE(packet);
}

TEST(UploadProcessor, wrong_username)
{
    /*wrong username*/
    processor->SetUserName("testun");
    Packet *packet = ALLOCATE(Packet);
    EXPECT_EQ(SMB_SUCCESS, processor->PacketCreator()->CreatePacket(packet, UPLOAD_INIT_REQ, NULL));
    EXPECT_EQ(SMB_ERROR, processor->ProcessRequest(packet));
    processor->SetUserName(test_un);
    packet->Reset();
    FREE(packet);
}

TEST(UploadProcessor, wrong_url)
{
    /*wrong url*/
    processor->SetUrl("test_url.com/share/folder");
    Packet *packet = ALLOCATE(Packet);
    EXPECT_EQ(SMB_SUCCESS, processor->PacketCreator()->CreatePacket(packet, UPLOAD_INIT_REQ, NULL));
    EXPECT_EQ(SMB_ERROR, processor->ProcessRequest(packet));
    processor->SetUrl(test_url+"/"+test_share+"/"+file);
    packet->Reset();
    FREE(packet);
}

TEST(UploadProcessor, success)
{
    system("cp ../unit-tests/datafiles/twrp.img .");
    std::string tmp("2345");
    Packet *packet = ALLOCATE(Packet);
    EXPECT_EQ(SMB_SUCCESS, processor->PacketCreator()->CreatePacket(packet, UPLOAD_INIT_REQ, NULL));
    processor->SetRequestId(tmp);
    EXPECT_EQ(SMB_ERROR, processor->ProcessRequest(packet));
    processor->SetRequestId("1234");
    packet->Reset();
    FREE(packet);
    server->GetSessionManager()->FreeAllResponse();
    packet = ALLOCATE(Packet);
    processor->OpenFile();
    EXPECT_EQ(SMB_SUCCESS, processor->PacketCreator()->CreatePacket(packet, UPLOAD_INIT_REQ, NULL));
    EXPECT_EQ(SMB_SUCCESS, processor->ProcessRequest(packet));
    while(1)
    {
        packet = server->GetSessionManager()->PopResponse();
        if(packet == NULL)
            continue;
        if(packet->GetCMD() == UPLOAD_END_REQ)
            break;
        EXPECT_EQ(SMB_SUCCESS, processor->ProcessRequest(packet));
        FREE(packet);
    }
    EXPECT_EQ(SMB_SUCCESS, processor->ProcessRequest(packet));
    packet->Reset();
    FREE(packet);
    unlink("twrp.img");
}

TEST(UploadProcessor, init_resp)
{
    Packet *packet = ALLOCATE(Packet);
    EXPECT_EQ(SMB_SUCCESS, processor->PacketCreator()->CreateStatusPacket(packet, UPLOAD_INIT_RESP, SMB_SUCCESS));
    EXPECT_EQ(SMB_SUCCESS, processor->ProcessRequest(packet));
    packet->Reset();
    FREE(packet);
}

TEST(UploadProcessor, error)
{
    Packet *packet = ALLOCATE(Packet);
    EXPECT_EQ(SMB_SUCCESS, processor->PacketCreator()->CreateStatusPacket(packet, UPLOAD_ERROR, 17, true));
    EXPECT_EQ(SMB_SUCCESS, processor->ProcessRequest(packet));
    packet->Reset();
    FREE(packet);
    packet = ALLOCATE(Packet);
    EXPECT_EQ(SMB_SUCCESS, processor->PacketCreator()->CreateStatusPacket(packet, UPLOAD_ERROR, SMB_ERROR, false));
    EXPECT_EQ(SMB_SUCCESS, processor->ProcessRequest(packet));
    packet->Reset();
    FREE(packet);
}

TEST(UploadProcessor, payload_end)
{
    Packet *packet = ALLOCATE(Packet);
    EXPECT_EQ(SMB_SUCCESS, processor->PacketCreator()->CreatePacket(packet, UPLOAD_END_REQ, NULL));
    EXPECT_EQ(SMB_SUCCESS, processor->ProcessRequest(packet));
    packet->Reset();
    FREE(packet);
}

TEST(UploadProcessor, Quit)
{
    should_exit = 1;
    processor->Quit();
    FREE(processor);
    FREE(server);
    processor = NULL;
}

#endif