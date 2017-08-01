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
#include "packet/UploadPacketCreator.h"

static IPacketCreator *packetCreator = NULL;
static RequestProcessor *processor = NULL;
static std::string request_id="1234";
TEST(UploadPacketCreator, Init)
{
    processor = ALLOCATE(UploadProcessor);
    EXPECT_EQ(SMB_SUCCESS, processor->Init(request_id));
    packetCreator = processor->PacketCreator();
    EXPECT_TRUE(processor != NULL);
    EXPECT_TRUE(packetCreator != NULL);
}

TEST(UploadPacketCreator, CreatePacket)
{
    RequestProcessor::SetInstance(NULL);
    Packet *packet = ALLOCATE(Packet);
    EXPECT_EQ(SMB_ERROR, packetCreator->CreatePacket(NULL, UPLOAD_INIT_REQ, NULL));
    EXPECT_EQ(SMB_ERROR, packetCreator->CreatePacket(packet, UPLOAD_INIT_REQ, NULL));
    EXPECT_EQ(SMB_ERROR, packetCreator->CreatePacket(packet, UPLOAD_INIT_RESP, NULL));
    EXPECT_EQ(SMB_ERROR, packetCreator->CreatePacket(packet, UPLOAD_DATA_REQ, NULL));
    EXPECT_EQ(SMB_ERROR, packetCreator->CreatePacket(packet, UPLOAD_END_REQ, NULL));
    EXPECT_EQ(SMB_ERROR, packetCreator->CreatePacket(packet, UPLOAD_END_RESP, NULL));
    EXPECT_EQ(SMB_ERROR, packetCreator->CreatePacket(packet, UPLOAD_ERROR, NULL));
    RequestProcessor::SetInstance(processor);
    EXPECT_EQ(SMB_SUCCESS, packetCreator->CreatePacket(packet, UPLOAD_INIT_REQ, NULL));
    EXPECT_EQ(SMB_ERROR, packetCreator->CreatePacket(packet, UPLOAD_INIT_RESP, NULL));
    EXPECT_EQ(SMB_ERROR, packetCreator->CreatePacket(packet, UPLOAD_DATA_REQ, NULL));
    packet_data data;
    data.download_upload_data.payload_len = 1;
    data.download_upload_data.payload = (char *)malloc(1);
    EXPECT_EQ(SMB_SUCCESS, packetCreator->CreatePacket(packet, UPLOAD_DATA_REQ, &data));
    EXPECT_EQ(SMB_SUCCESS, packetCreator->CreatePacket(packet, UPLOAD_END_REQ, NULL));
    EXPECT_EQ(SMB_ERROR, packetCreator->CreatePacket(packet, UPLOAD_ERROR, NULL));
    EXPECT_EQ(SMB_ERROR, packetCreator->CreatePacket(packet, UPLOAD_END_RESP, NULL));
    EXPECT_EQ(SMB_ERROR, packetCreator->CreatePacket(packet, UPLOAD_ERROR, NULL));
    RequestProcessor::SetInstance(NULL);
    processor->Quit();
    FREE(processor);
}

#endif

