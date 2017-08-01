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
#include "packet/DownloadPacketCreator.h"

static IPacketCreator *packetCreator = NULL;
static RequestProcessor *processor = NULL;
static std::string request_id="1234";
TEST(DownloadPacketCreator, Init)
{
    processor = ALLOCATE(DownloadProcessor);
    EXPECT_EQ(SMB_SUCCESS, processor->Init(request_id));
    packetCreator = processor->PacketCreator();
    EXPECT_TRUE(processor != NULL);
    EXPECT_TRUE(packetCreator != NULL);
}

TEST(DownloadPacketCreator, CreatePacket)
{
    RequestProcessor::SetInstance(NULL);
    Packet *packet = ALLOCATE(Packet);
    EXPECT_EQ(SMB_ERROR, packetCreator->CreatePacket(NULL, DOWNLOAD_INIT_REQ, NULL));
    EXPECT_EQ(SMB_ERROR, packetCreator->CreatePacket(packet, DOWNLOAD_INIT_REQ, NULL));
    EXPECT_EQ(SMB_ERROR, packetCreator->CreatePacket(packet, DOWNLOAD_INIT_RESP, NULL));
    EXPECT_EQ(SMB_ERROR, packetCreator->CreatePacket(packet, DOWNLOAD_DATA_REQ, NULL));
    EXPECT_EQ(SMB_ERROR, packetCreator->CreatePacket(packet, DOWNLOAD_DATA_RESP, NULL));
    EXPECT_EQ(SMB_ERROR, packetCreator->CreatePacket(packet, DOWNLOAD_END_RESP, NULL));
    EXPECT_EQ(SMB_ERROR, packetCreator->CreatePacket(packet, DOWNLOAD_ERROR, NULL));
    RequestProcessor::SetInstance(processor);
    EXPECT_EQ(SMB_SUCCESS, packetCreator->CreatePacket(packet, DOWNLOAD_INIT_REQ, NULL));
    EXPECT_EQ(SMB_SUCCESS, packetCreator->CreatePacket(packet, DOWNLOAD_INIT_RESP, NULL));
    EXPECT_EQ(SMB_ERROR, packetCreator->CreatePacket(packet, DOWNLOAD_DATA_REQ, NULL));
    packet_data data;
    data.dowload_req_data.start = 1;
    data.dowload_req_data.end = 2;
    data.dowload_req_data.chunk_size = 5;
    EXPECT_EQ(SMB_SUCCESS, packetCreator->CreatePacket(packet, DOWNLOAD_DATA_REQ, &data));
    EXPECT_EQ(SMB_ERROR, packetCreator->CreatePacket(packet, DOWNLOAD_DATA_RESP, NULL));
    data.download_upload_data.payload_len = 1;
    data.download_upload_data.payload = (char *)malloc(1);
    EXPECT_EQ(SMB_SUCCESS, packetCreator->CreatePacket(packet, DOWNLOAD_DATA_RESP, &data));
    EXPECT_EQ(SMB_SUCCESS, packetCreator->CreatePacket(packet, DOWNLOAD_END_RESP, NULL));
    EXPECT_EQ(SMB_ERROR, packetCreator->CreatePacket(packet, DOWNLOAD_ERROR, NULL));
    RequestProcessor::SetInstance(NULL);
    processor->Quit();
    FREE(processor);
}

#endif

