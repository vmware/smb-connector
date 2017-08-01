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
#include "packet/DownloadPacketParser.h"

static IPacketParser *parser = NULL;
static IPacketCreator *creator = NULL;
static DownloadProcessor *processor = NULL;
static std::string request_id="1234";

static std::string un = "test";
static std::string pass = "password";
static std::string server = "example.com";
static std::string wg = "workgroup";

TEST(DownloadParser, Setup)
{
    processor = ALLOCATE(DownloadProcessor);
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
    processor->SetChunkSize(65536);
    processor->SetStartOffset(0);
    processor->SetEndOffset(124);
    processor->SetModifiedTime(123456);
    processor->SetCreateTime(456789);
}

TEST(DownloadParser, ParsePacket)
{
    std::string wrong_request_id = "2345";
    packet_data data;
    data.dowload_req_data.start = 0;
    data.dowload_req_data.end = 1234;
    data.dowload_req_data.chunk_size = 65536;
    Packet *packet = ALLOCATE(Packet);
    EXPECT_EQ(SMB_SUCCESS, creator->CreatePacket(packet, DOWNLOAD_INIT_REQ, NULL));
    RequestProcessor::GetInstance()->SetRequestId(wrong_request_id);
    EXPECT_EQ(SMB_ERROR, parser->ParsePacket(packet));
    RequestProcessor::GetInstance()->SetRequestId(request_id);
    EXPECT_EQ(SMB_SUCCESS, creator->CreatePacket(packet, DOWNLOAD_INIT_REQ, NULL));
    EXPECT_EQ(SMB_SUCCESS, parser->ParsePacket(packet));
    EXPECT_EQ(SMB_SUCCESS, creator->CreatePacket(packet, DOWNLOAD_INIT_RESP, NULL));
    EXPECT_EQ(SMB_SUCCESS, parser->ParsePacket(packet));
    EXPECT_EQ(SMB_SUCCESS, creator->CreatePacket(packet, DOWNLOAD_DATA_REQ, &data));
    EXPECT_EQ(SMB_SUCCESS, parser->ParsePacket(packet));
    memset(&data, 0, sizeof(data));
    data.download_upload_data.payload = ALLOCATE_ARR(char, 100);
    data.download_upload_data.payload_len = 100;
    EXPECT_EQ(SMB_SUCCESS, creator->CreatePacket(packet, DOWNLOAD_DATA_RESP, &data));
    EXPECT_EQ(SMB_SUCCESS, parser->ParsePacket(packet));
    FREE_ARR(data.download_upload_data.payload);
    EXPECT_EQ(SMB_SUCCESS, creator->CreatePacket(packet, DOWNLOAD_END_RESP, &data));
    EXPECT_EQ(SMB_SUCCESS, parser->ParsePacket(packet));
    EXPECT_EQ(SMB_SUCCESS, creator->CreateStatusPacket(packet, DOWNLOAD_ERROR, 0));
    EXPECT_EQ(SMB_SUCCESS, parser->ParsePacket(packet));
}

TEST(DownloadParser, TearDown)
{
    RequestProcessor::SetInstance(NULL);
    processor->Quit();
    FREE(processor);
}

#endif //_DEBUG_