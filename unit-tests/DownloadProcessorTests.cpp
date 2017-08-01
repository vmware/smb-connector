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
#include "processor/DownloadProcessor.h"
#include "core/Server.h"

extern std::string test_url;
extern std::string test_un;
extern std::string test_pass;
extern std::string test_wg;
extern std::string test_share;

extern std::string request_id;
extern UnixDomainSocket sock;

static DownloadProcessor *processor = NULL;
static std::string file="twrp.img";
static Server *server = NULL;

TEST(DownloadProcessor, Init)
{
    should_exit = 1;
    server = ALLOCATE(Server);
    Configuration &c = Configuration::GetInstance();
    c.Set(C_BUFFER_SIZE, "1000");
    server->GetSessionManager()->Init(server);
    processor = ALLOCATE(DownloadProcessor);
    RequestProcessor::SetInstance(processor);
    processor->SetSessionManager(server->GetSessionManager());
    processor->SetUrl(test_url+"/"+test_share+"/"+file);
    processor->SetWorkGroup(test_wg);
    processor->SetUserName(test_un);
    processor->SetPassword(test_pass);
    EXPECT_EQ(SMB_SUCCESS, processor->Init(request_id));
}

TEST(DownloadProcessor, wrong_password)
{
    /*wrong password */
    processor->SetPassword("123456");
    Packet *packet = ALLOCATE(Packet);
    EXPECT_EQ(SMB_SUCCESS, processor->PacketCreator()->CreatePacket(packet, DOWNLOAD_INIT_REQ, NULL));
    EXPECT_EQ(SMB_ERROR, processor->ProcessRequest(packet));
    processor->SetPassword(test_pass);
    packet->Reset();
    FREE(packet);
}

TEST(DownloadProcessor, wrong_username)
{
    /*wrong username*/
    processor->SetUserName("testun");
    Packet *packet = ALLOCATE(Packet);
    EXPECT_EQ(SMB_SUCCESS, processor->PacketCreator()->CreatePacket(packet, DOWNLOAD_INIT_REQ, NULL));
    EXPECT_EQ(SMB_ERROR, processor->ProcessRequest(packet));
    processor->SetUserName(test_un);
    packet->Reset();
    FREE(packet);
}

TEST(DownloadProcessor, wrong_url)
{
    /*wrong url*/
    processor->SetUrl("test_url.com/share/folder");
    Packet *packet = ALLOCATE(Packet);
    EXPECT_EQ(SMB_SUCCESS, processor->PacketCreator()->CreatePacket(packet, DOWNLOAD_INIT_REQ, NULL));
    EXPECT_EQ(SMB_ERROR, processor->ProcessRequest(packet));
    processor->SetUrl(test_url+"/"+test_share+"/"+file);
    packet->Reset();
    FREE(packet);
}

TEST(DownloadProcessor, success)
{
    std::string tmp("2345");
    Packet *packet = ALLOCATE(Packet);
    EXPECT_EQ(SMB_SUCCESS, processor->PacketCreator()->CreatePacket(packet, DOWNLOAD_INIT_REQ, NULL));
    processor->SetRequestId(tmp);
    EXPECT_EQ(SMB_ERROR, processor->ProcessRequest(packet));
    processor->SetRequestId("1234");
    packet->Reset();
    FREE(packet);
    server->GetSessionManager()->FreeAllResponse();
    packet = ALLOCATE(Packet);
    EXPECT_EQ(SMB_SUCCESS, processor->PacketCreator()->CreatePacket(packet, DOWNLOAD_INIT_REQ, NULL));
    EXPECT_EQ(SMB_SUCCESS, processor->ProcessRequest(packet));
    while(1)
    {
        packet = server->GetSessionManager()->PopResponse();
        if(packet == NULL)
            continue;
        if(packet->GetCMD() == DOWNLOAD_END_RESP)
            break;
        EXPECT_EQ(SMB_SUCCESS, processor->ProcessRequest(packet));
        FREE(packet);
    }
    EXPECT_EQ(SMB_SUCCESS, processor->ProcessRequest(packet));
    packet->Reset();
    FREE(packet);
}

TEST(DownloadProcessor, init_resp)
{
    Packet *packet = ALLOCATE(Packet);
    EXPECT_EQ(SMB_SUCCESS, processor->PacketCreator()->CreatePacket(packet, DOWNLOAD_INIT_RESP, NULL));
    EXPECT_EQ(SMB_SUCCESS, processor->ProcessRequest(packet));
    packet->Reset();
    FREE(packet);
}

TEST(DownloadProcessor, error)
{
    Packet *packet = ALLOCATE(Packet);
    EXPECT_EQ(SMB_SUCCESS, processor->PacketCreator()->CreateStatusPacket(packet, DOWNLOAD_ERROR, 17, true));
    EXPECT_EQ(SMB_SUCCESS, processor->ProcessRequest(packet));
    packet->Reset();
    FREE(packet);
    packet = ALLOCATE(Packet);
    EXPECT_EQ(SMB_SUCCESS, processor->PacketCreator()->CreateStatusPacket(packet, DOWNLOAD_ERROR, SMB_ERROR, false));
    EXPECT_EQ(SMB_SUCCESS, processor->ProcessRequest(packet));
    packet->Reset();
    FREE(packet);
}

TEST(DownloadProcessor, payload)
{
    Packet *packet = ALLOCATE(Packet);
    struct packet_upload_download_data param;
    param.payload = (char *)"test";
    param.payload_len = 5;
    EXPECT_EQ(SMB_SUCCESS, processor->PacketCreator()->CreatePacket(packet, DOWNLOAD_DATA_RESP, &param));
    EXPECT_EQ(SMB_SUCCESS, processor->ProcessRequest(packet));
    packet->Reset();
    FREE(packet);
}

TEST(DownloadProcessor, payload_end)
{
    Packet *packet = ALLOCATE(Packet);
    EXPECT_EQ(SMB_SUCCESS, processor->PacketCreator()->CreatePacket(packet, DOWNLOAD_END_RESP, NULL));
    EXPECT_EQ(SMB_SUCCESS, processor->ProcessRequest(packet));
    packet->Reset();
    FREE(packet);
}

TEST(DownloadProcessor, Quit)
{
    should_exit = 1;
    processor->Quit();
    FREE(processor);
    FREE(server);
    processor = NULL;
}

#endif