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
#include "packet/OpenDirPacketCreator.h"

static IPacketCreator *packetCreator = NULL;
static OpenDirReqProcessor *processor = NULL;
static std::string request_id="1234";
TEST(OpenDirPacketCreator, Init)
{
    processor = ALLOCATE(OpenDirReqProcessor);
    EXPECT_EQ(SMB_SUCCESS, processor->Init(request_id));
    packetCreator = processor->PacketCreator();
    EXPECT_TRUE(processor != NULL);
    EXPECT_TRUE(packetCreator != NULL);
}

TEST(OpenDirPacketCreator, CreatePacket)
{
    RequestProcessor::SetInstance(NULL);
    Packet *packet = ALLOCATE(Packet);
    EXPECT_EQ(SMB_ERROR, packetCreator->CreatePacket(NULL, GET_STRUCTURE_INIT_REQ, NULL));
    EXPECT_EQ(SMB_ERROR, packetCreator->CreatePacket(packet, GET_STRUCTURE_INIT_REQ, NULL));
    EXPECT_EQ(SMB_ERROR, packetCreator->CreatePacket(packet, GET_STRUCTURE_INIT_RESP, NULL));
    EXPECT_EQ(SMB_ERROR, packetCreator->CreatePacket(packet, GET_STRUCTURE_END_RESP, NULL));
    EXPECT_EQ(SMB_ERROR, packetCreator->CreatePacket(packet, GET_STRUCTURE_ERROR_RESP, NULL));
    RequestProcessor::SetInstance(processor);
    EXPECT_EQ(SMB_SUCCESS, packetCreator->CreatePacket(packet, GET_STRUCTURE_INIT_REQ, NULL));
    EXPECT_EQ(SMB_AGAIN, packetCreator->CreatePacket(packet, GET_STRUCTURE_INIT_RESP, NULL));
    EXPECT_EQ(SMB_SUCCESS, packetCreator->CreatePacket(packet, GET_STRUCTURE_END_RESP, NULL));
    EXPECT_EQ(SMB_ERROR, packetCreator->CreatePacket(packet, GET_STRUCTURE_ERROR_RESP, NULL));

    processor->SetIsDirectory(true);
    EXPECT_EQ(SMB_AGAIN, packetCreator->CreatePacket(packet, GET_STRUCTURE_INIT_RESP, NULL));

    RequestProcessor::SetInstance(NULL);
    processor->Quit();
    FREE(processor);
}

#endif

