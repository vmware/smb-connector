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
#include "packet/DeletePacketParser.h"

static IPacketParser *parser = NULL;
static IPacketCreator *creator = NULL;
static RequestProcessor *processor = NULL;
static std::string request_id="1234";

static std::string un = "test";
static std::string pass = "password";
static std::string server = "example.com";
static std::string wg = "workgroup";

TEST(DeleteParser, Setup)
{
    processor = ALLOCATE(DeleteProcessor);
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
}

TEST(DeleteParser, ParsePacket)
{
    std::string wrong_request_id = "2345";
    bool isDirectory = false;
    Packet *packet = ALLOCATE(Packet);
    EXPECT_EQ(SMB_SUCCESS, creator->CreatePacket(packet, DELETE_INIT_REQ, NULL));
    RequestProcessor::GetInstance()->SetRequestId(wrong_request_id);
    EXPECT_EQ(SMB_ERROR, parser->ParsePacket(packet));
    RequestProcessor::GetInstance()->SetRequestId(request_id);
    EXPECT_EQ(SMB_SUCCESS, creator->CreatePacket(packet, DELETE_INIT_REQ, NULL));
    EXPECT_EQ(SMB_SUCCESS, parser->ParsePacket(packet));
    EXPECT_EQ(SMB_SUCCESS, creator->CreatePacket(packet, DELETE_INIT_RESP, &isDirectory));
    EXPECT_EQ(SMB_SUCCESS, parser->ParsePacket(packet));
    EXPECT_EQ(SMB_SUCCESS, creator->CreateStatusPacket(packet, DELETE_ERROR_RESP, 0));
    EXPECT_EQ(SMB_SUCCESS, parser->ParsePacket(packet));
}

TEST(DeleteParser, TearDown)
{
    RequestProcessor::SetInstance(NULL);
    processor->Quit();
    FREE(processor);
}

#endif //_DEBUG_