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
#include "packet/OpenDirReqPacketParser.h"

static IPacketParser *parser = NULL;
static IPacketCreator *creator = NULL;
static OpenDirReqProcessor *processor = NULL;
static std::string request_id="1234";

static std::string un = "test";
static std::string pass = "password";
static std::string server = "example.com";
static std::string wg = "workgroup";

TEST(OpenDirReqParser, Setup)
{
    processor = ALLOCATE(OpenDirReqProcessor);
    EXPECT_EQ(SMB_SUCCESS, processor->Init(request_id));
    parser = processor->PacketParser();
    creator = processor->PacketCreator();
    EXPECT_TRUE(processor != NULL);
    EXPECT_TRUE(parser != NULL);
    EXPECT_TRUE(creator != NULL);
    RequestProcessor::SetInstance(processor);
    processor->SetUrl(server);
    processor->SetUserName(un);
    processor->SetPassword(pass);
    processor->SetWorkGroup(wg);
    processor->SetPageSize(5);
    processor->SetShowOnlyFolders(true);
    processor->SetShowHiddenFiles(true);
    processor->SetIsDirectory(false);
}

TEST(OpenDirReqParser, ParsePacket)
{
    std::string wrong_request_id = "2345";
    Packet *packet = ALLOCATE(Packet);
    EXPECT_EQ(SMB_SUCCESS, creator->CreatePacket(packet, GET_STRUCTURE_INIT_REQ, NULL));
    RequestProcessor::GetInstance()->SetRequestId(wrong_request_id);
    EXPECT_EQ(SMB_ERROR, parser->ParsePacket(packet));
    RequestProcessor::GetInstance()->SetRequestId(request_id);
    EXPECT_EQ(SMB_SUCCESS, creator->CreatePacket(packet, GET_STRUCTURE_INIT_REQ, NULL));
    EXPECT_EQ(SMB_SUCCESS, parser->ParsePacket(packet));
    EXPECT_EQ(SMB_SUCCESS, creator->CreatePacket(packet, GET_STRUCTURE_INIT_RESP, NULL));
    EXPECT_EQ(SMB_SUCCESS, parser->ParsePacket(packet));
    EXPECT_EQ(SMB_SUCCESS, creator->CreatePacket(packet, GET_STRUCTURE_END_RESP, NULL));
    EXPECT_EQ(SMB_SUCCESS, parser->ParsePacket(packet));
    EXPECT_EQ(SMB_SUCCESS, creator->CreateStatusPacket(packet, GET_STRUCTURE_ERROR_RESP, 0));
    EXPECT_EQ(SMB_SUCCESS, parser->ParsePacket(packet));
}

TEST(OpenDirReqParser, TearDown)
{
    RequestProcessor::SetInstance(NULL);
    processor->Quit();
    FREE(processor);
}

#endif //_DEBUG_

