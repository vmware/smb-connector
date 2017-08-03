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
#include "processor/AddFolderProcessor.h"
#include "core/Server.h"

/* Global variables used by all processor impl */

std::string test_url = "127.0.0.1";
std::string test_un = "test";
std::string test_pass = "test";
std::string test_wg = "test";
std::string test_share = "test";

std::string request_id = "1234";
UnixDomainSocket sock;

static AddFolderProcessor *processor = NULL;
static std::string folder = "unit_test";
static struct stat *_stat = NULL;
static Server *server = NULL;

Configuration &c = Configuration::GetInstance();

TEST(AddFolderProcessor, Init)
{
    c.Set(C_SMB_CONF, "../smb.conf");
    c.Set(C_CONF_FILE, "../smb-connector.conf");
    should_exit = 1;
    server = ALLOCATE(Server);
    processor = ALLOCATE(AddFolderProcessor);
    RequestProcessor::SetInstance(processor);
    processor->SetSessionManager(server->GetSessionManager());
    processor->SetUrl(test_url+"/"+test_share+"/"+folder);
    processor->SetWorkGroup(test_wg);
    processor->SetUserName(test_un);
    processor->SetPassword(test_pass);
    EXPECT_EQ(SMB_SUCCESS, processor->Init(request_id));
}

TEST(AddFolderProcessor, add_folder_req_wrong_password)
{
    /*wrong password */
    processor->SetPassword("123456");
    Packet *packet = ALLOCATE(Packet);
    EXPECT_EQ(SMB_SUCCESS, processor->PacketCreator()->CreatePacket(packet, ADD_FOLDER_INIT_REQ, NULL));
    EXPECT_EQ(SMB_ERROR, processor->ProcessRequest(packet));
    processor->SetPassword(test_pass);
    packet->Reset();
    FREE(packet);
}

TEST(AddFolderProcessor, add_folder_req_wrong_username)
{
    /*wrong username*/
    processor->SetUserName("testun");
    Packet *packet = ALLOCATE(Packet);
    EXPECT_EQ(SMB_SUCCESS, processor->PacketCreator()->CreatePacket(packet, ADD_FOLDER_INIT_REQ, NULL));
    EXPECT_EQ(SMB_ERROR, processor->ProcessRequest(packet));
    processor->SetUserName(test_un);
    packet->Reset();
    FREE(packet);
}

TEST(AddFolderProcessor, add_folder_req_wrong_url)
{
    /*wrong url*/
    processor->SetUrl("test_url.com/share/folder");
    Packet *packet = ALLOCATE(Packet);
    EXPECT_EQ(SMB_SUCCESS, processor->PacketCreator()->CreatePacket(packet, ADD_FOLDER_INIT_REQ, NULL));
    EXPECT_EQ(SMB_ERROR, processor->ProcessRequest(packet));
    processor->SetUrl(test_url+"/"+test_share+"/"+folder);
    packet->Reset();
    FREE(packet);
}

TEST(AddFolderProcessor, add_folder_req_success)
{
    std::string wrng_request_id = "2355";
    Packet *packet = ALLOCATE(Packet);
    EXPECT_EQ(SMB_SUCCESS, processor->PacketCreator()->CreatePacket(packet, ADD_FOLDER_INIT_REQ, NULL));
    processor->SetRequestId(wrng_request_id);
    EXPECT_EQ(SMB_ERROR, processor->ProcessRequest(packet));
    processor->SetRequestId(request_id);
    packet->Reset();
    FREE(packet);
    packet = ALLOCATE(Packet);
    EXPECT_EQ(SMB_SUCCESS, processor->PacketCreator()->CreatePacket(packet, ADD_FOLDER_INIT_REQ, NULL));
    EXPECT_EQ(SMB_SUCCESS, processor->ProcessRequest(packet));
    packet->Reset();
    FREE(packet);

    processor->SetUrl(processor->Url()+"/nested1");
    packet = ALLOCATE(Packet);
    EXPECT_EQ(SMB_SUCCESS, processor->PacketCreator()->CreatePacket(packet, ADD_FOLDER_INIT_REQ, NULL));
    EXPECT_EQ(SMB_SUCCESS, processor->ProcessRequest(packet));
    packet->Reset();
    FREE(packet);

    processor->SetUrl(processor->Url()+"/nested2");
    packet = ALLOCATE(Packet);
    EXPECT_EQ(SMB_SUCCESS, processor->PacketCreator()->CreatePacket(packet, ADD_FOLDER_INIT_REQ, NULL));
    EXPECT_EQ(SMB_SUCCESS, processor->ProcessRequest(packet));
    packet->Reset();
    FREE(packet);
}

TEST(AddFolderProcessor, add_folder_resp)
{
    _stat = processor->GetStat();
    EXPECT_TRUE(_stat != NULL);
    Packet *packet = ALLOCATE(Packet);
    EXPECT_EQ(SMB_SUCCESS, processor->PacketCreator()->CreatePacket(packet, ADD_FOLDER_INIT_RESP, NULL));
    EXPECT_EQ(SMB_SUCCESS, processor->ProcessRequest(packet));
    packet->Reset();
    FREE(packet);
}

TEST(AddFolderProcessor, add_folder_error)
{
    Packet *packet = ALLOCATE(Packet);
    EXPECT_EQ(SMB_SUCCESS, processor->PacketCreator()->CreateStatusPacket(packet, ADD_FOLDER_ERROR_RESP, 17, true));
    EXPECT_EQ(SMB_SUCCESS, processor->ProcessRequest(packet));
    packet->Reset();
    FREE(packet);
    packet = ALLOCATE(Packet);
    EXPECT_EQ(SMB_SUCCESS, processor->PacketCreator()->CreateStatusPacket(packet, ADD_FOLDER_ERROR_RESP, SMB_ERROR, false));
    EXPECT_EQ(SMB_SUCCESS, processor->ProcessRequest(packet));
    packet->Reset();
    FREE(packet);
}

TEST(AddFolderProcessor, Quit)
{
    should_exit = 1;
    processor->Quit();
    FREE(processor);
    FREE(server);
    processor = NULL;
}

#endif
