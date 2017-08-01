/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#ifdef _DEBUG_
#include <gtest/gtest.h>
#include "base/Configuration.h"

TEST(Configuration, ALLTests)
{
    Configuration &c = Configuration::GetInstance();
    c.Reset();
    c.DumpTable();

    c.Set("TEST", "test");
    EXPECT_EQ(strcmp(c["TEST"], "test"), 0);

    c.Set("TEST", "test1");
    EXPECT_EQ(strcmp(c["TEST"], "test1"), 0);
    c.Reset();
    EXPECT_EQ(strcmp(c["TEST"], ""), 0);

    c.Set("TEST", 1);
    EXPECT_EQ(strcmp(c["TEST"], "1"), 0);

    c.Set(NULL, "test");
    c.Set("test", (const char*)NULL);
}

#endif //_DEBUG_
