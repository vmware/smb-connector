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
#include "packet/TestConnectionPacketCreator.h"

static IPacketCreator *packetCreator = NULL;
static RequestProcessor *processor = NULL;
static std::string request_id="1234";
TEST(TestConnectionPacketCreator, Init)
{
    processor = ALLOCATE(TestConnection);
    EXPECT_EQ(SMB_SUCCESS, processor->Init(request_id));
    packetCreator = processor->PacketCreator();
    EXPECT_TRUE(processor != NULL);
    EXPECT_TRUE(packetCreator != NULL);
}

TEST(TestConnectionPacketCreator, CreatePacket)
{
    RequestProcessor::SetInstance(NULL);
    Packet *packet = ALLOCATE(Packet);
    EXPECT_EQ(SMB_ERROR, packetCreator->CreatePacket(NULL, TEST_CONNECTION_INIT_REQ, NULL));
    EXPECT_EQ(SMB_ERROR, packetCreator->CreatePacket(packet, TEST_CONNECTION_INIT_REQ, NULL));
    EXPECT_EQ(SMB_ERROR, packetCreator->CreatePacket(packet, TEST_CONNECTION_INIT_RESP, NULL));
    EXPECT_EQ(SMB_ERROR, packetCreator->CreatePacket(packet, TEST_CONNECTION_ERROR_RESP, NULL));
    RequestProcessor::SetInstance(processor);
    EXPECT_EQ(SMB_SUCCESS, packetCreator->CreatePacket(packet, TEST_CONNECTION_INIT_REQ, NULL));
    EXPECT_EQ(SMB_SUCCESS, packetCreator->CreatePacket(packet, TEST_CONNECTION_INIT_RESP, NULL));
    EXPECT_EQ(SMB_ERROR, packetCreator->CreatePacket(packet, ADD_FOLDER_INIT_REQ, NULL));
    RequestProcessor::SetInstance(NULL);
    processor->Quit();
    FREE(processor);
}

#endif

