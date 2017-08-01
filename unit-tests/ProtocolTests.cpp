/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#ifdef _DEBUG_
#include <gtest/gtest.h>
#include "base/Protocol.h"

TEST(Protocol, ProtocolCommand)
{
    EXPECT_TRUE(strcmp(ProtocolCommand(GET_STRUCTURE_INIT_REQ), "GET_STRUCTURE_INIT_REQ") == 0);
    EXPECT_TRUE(strcmp(ProtocolCommand(GET_STRUCTURE_INIT_RESP), "GET_STRUCTURE_INIT_RESP") == 0);
    EXPECT_TRUE(strcmp(ProtocolCommand(GET_STRUCTURE_END_RESP), "GET_STRUCTURE_END_RESP") == 0);
    EXPECT_TRUE(strcmp(ProtocolCommand(GET_STRUCTURE_ERROR_RESP), "GET_STRUCTURE_ERROR_RESP") == 0);

    EXPECT_TRUE(strcmp(ProtocolCommand(DOWNLOAD_INIT_REQ), "DOWNLOAD_INIT_REQ") == 0);
    EXPECT_TRUE(strcmp(ProtocolCommand(DOWNLOAD_INIT_RESP), "DOWNLOAD_INIT_RESP") == 0);
    EXPECT_TRUE(strcmp(ProtocolCommand(DOWNLOAD_DATA_REQ), "DOWNLOAD_DATA_REQ") == 0);
    EXPECT_TRUE(strcmp(ProtocolCommand(DOWNLOAD_DATA_RESP), "DOWNLOAD_DATA_RESP") == 0);
    EXPECT_TRUE(strcmp(ProtocolCommand(DOWNLOAD_END_RESP), "DOWNLOAD_END_RESP") == 0);
    EXPECT_TRUE(strcmp(ProtocolCommand(DOWNLOAD_ERROR), "DOWNLOAD_ERROR") == 0);

    EXPECT_TRUE(strcmp(ProtocolCommand(UPLOAD_INIT_REQ), "UPLOAD_INIT_REQ") == 0);
    EXPECT_TRUE(strcmp(ProtocolCommand(UPLOAD_INIT_RESP), "UPLOAD_INIT_RESP") == 0);
    EXPECT_TRUE(strcmp(ProtocolCommand(UPLOAD_DATA_REQ), "UPLOAD_DATA_REQ") == 0);
    EXPECT_TRUE(strcmp(ProtocolCommand(UPLOAD_END_RESP), "UPLOAD_END_RESP") == 0);
    EXPECT_TRUE(strcmp(ProtocolCommand(UPLOAD_END_REQ), "UPLOAD_END_REQ") == 0);
    EXPECT_TRUE(strcmp(ProtocolCommand(UPLOAD_ERROR), "UPLOAD_ERROR") == 0);

    EXPECT_TRUE(strcmp(ProtocolCommand(ADD_FOLDER_INIT_REQ), "ADD_FOLDER_INIT_REQ") == 0);
    EXPECT_TRUE(strcmp(ProtocolCommand(ADD_FOLDER_INIT_RESP), "ADD_FOLDER_INIT_RESP") == 0);
    EXPECT_TRUE(strcmp(ProtocolCommand(ADD_FOLDER_ERROR_RESP), "ADD_FOLDER_ERROR_RESP") == 0);

    EXPECT_TRUE(strcmp(ProtocolCommand(DELETE_INIT_REQ), "DELETE_INIT_REQ") == 0);
    EXPECT_TRUE(strcmp(ProtocolCommand(DELETE_INIT_RESP), "DELETE_INIT_RESP") == 0);
    EXPECT_TRUE(strcmp(ProtocolCommand(DELETE_ERROR_RESP), "DELETE_ERROR_RESP") == 0);

    EXPECT_TRUE(strcmp(ProtocolCommand(TEST_CONNECTION_INIT_REQ), "TEST_CONNECTION_INIT_REQ") == 0);
    EXPECT_TRUE(strcmp(ProtocolCommand(TEST_CONNECTION_INIT_RESP), "TEST_CONNECTION_INIT_RESP") == 0);
    EXPECT_TRUE(strcmp(ProtocolCommand(TEST_CONNECTION_ERROR_RESP), "TEST_CONNECTION_ERROR_RESP") == 0);

    EXPECT_TRUE(strcmp(ProtocolCommand(157), "INVALID_COMMAND") == 0);

}
#endif //_DEBUG_