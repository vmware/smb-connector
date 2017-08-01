/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#ifdef _DEBUG_
#include <gtest/gtest.h>
#include "base/Log.h"

extern int logLevel;

TEST(Log, ALLTests)
{
    logLevel = LOG_LVL_NONE;
    DEBUG_LOG("test %d %s", 1, "hello");
    WARNING_LOG("test %d %s", 1, "hello");
    INFO_LOG("test %d %s", 1, "hello");
    ERROR_LOG("test %d %s", 1, "hello");
    TRACE_LOG("test %d %s", 1, "hello");
    ALWAYS_LOG("test %d %s", 1, "hello");

    Log_smbclient(NULL, LOG_LVL_DEBUG, "test msg from smbclient");
    Log_smbclient(NULL, LOG_LVL_WARNING, "test msg from smbclient");
    Log_smbclient(NULL, LOG_LVL_INFO, "test msg from smbclient");
    Log_smbclient(NULL, LOG_LVL_ERROR, "test msg from smbclient");
    Log_smbclient(NULL, LOG_LVL_TRACE, "test msg from smbclient");
    Log_smbclient(NULL, LOG_LVL_ALWAYS, "test msg from smbclient");

    logLevel = LOG_LVL_WARNING;
    DEBUG_LOG("test %d %s", 1, "hello");
    WARNING_LOG("test %d %s", 1, "hello");
    INFO_LOG("test %d %s", 1, "hello");
    ERROR_LOG("test %d %s", 1, "hello");
    TRACE_LOG("test %d %s", 1, "hello");
    ALWAYS_LOG("test %d %s", 1, "hello");

    Log_smbclient(NULL, LOG_LVL_DEBUG, "test msg from smbclient");
    Log_smbclient(NULL, LOG_LVL_WARNING, "test msg from smbclient");
    Log_smbclient(NULL, LOG_LVL_INFO, "test msg from smbclient");
    Log_smbclient(NULL, LOG_LVL_ERROR, "test msg from smbclient");
    Log_smbclient(NULL, LOG_LVL_TRACE, "test msg from smbclient");
    Log_smbclient(NULL, LOG_LVL_ALWAYS, "test msg from smbclient");

    logLevel = LOG_LVL_INFO;
    DEBUG_LOG("test %d %s", 1, "hello");
    WARNING_LOG("test %d %s", 1, "hello");
    INFO_LOG("test %d %s", 1, "hello");
    ERROR_LOG("test %d %s", 1, "hello");
    TRACE_LOG("test %d %s", 1, "hello");
    ALWAYS_LOG("test %d %s", 1, "hello");

    Log_smbclient(NULL, LOG_LVL_DEBUG, "test msg from smbclient");
    Log_smbclient(NULL, LOG_LVL_WARNING, "test msg from smbclient");
    Log_smbclient(NULL, LOG_LVL_INFO, "test msg from smbclient");
    Log_smbclient(NULL, LOG_LVL_ERROR, "test msg from smbclient");
    Log_smbclient(NULL, LOG_LVL_TRACE, "test msg from smbclient");
    Log_smbclient(NULL, LOG_LVL_ALWAYS, "test msg from smbclient");

    logLevel = LOG_LVL_ERROR;
    DEBUG_LOG("test %d %s", 1, "hello");
    WARNING_LOG("test %d %s", 1, "hello");
    INFO_LOG("test %d %s", 1, "hello");
    ERROR_LOG("test %d %s", 1, "hello");
    TRACE_LOG("test %d %s", 1, "hello");
    ALWAYS_LOG("test %d %s", 1, "hello");

    Log_smbclient(NULL, LOG_LVL_DEBUG, "test msg from smbclient");
    Log_smbclient(NULL, LOG_LVL_WARNING, "test msg from smbclient");
    Log_smbclient(NULL, LOG_LVL_INFO, "test msg from smbclient");
    Log_smbclient(NULL, LOG_LVL_ERROR, "test msg from smbclient");
    Log_smbclient(NULL, LOG_LVL_TRACE, "test msg from smbclient");
    Log_smbclient(NULL, LOG_LVL_ALWAYS, "test msg from smbclient");

    logLevel = LOG_LVL_TRACE;
    DEBUG_LOG("test %d %s", 1, "hello");
    WARNING_LOG("test %d %s", 1, "hello");
    INFO_LOG("test %d %s", 1, "hello");
    ERROR_LOG("test %d %s", 1, "hello");
    TRACE_LOG("test %d %s", 1, "hello");
    ALWAYS_LOG("test %d %s", 1, "hello");

    Log_smbclient(NULL, LOG_LVL_DEBUG, "test msg from smbclient");
    Log_smbclient(NULL, LOG_LVL_WARNING, "test msg from smbclient");
    Log_smbclient(NULL, LOG_LVL_INFO, "test msg from smbclient");
    Log_smbclient(NULL, LOG_LVL_ERROR, "test msg from smbclient");
    Log_smbclient(NULL, LOG_LVL_TRACE, "test msg from smbclient");
    Log_smbclient(NULL, LOG_LVL_ALWAYS, "test msg from smbclient");

    logLevel = LOG_LVL_ALWAYS;
    DEBUG_LOG("test %d %s", 1, "hello");
    WARNING_LOG("test %d %s", 1, "hello");
    INFO_LOG("test %d %s", 1, "hello");
    ERROR_LOG("test %d %s", 1, "hello");
    TRACE_LOG("test %d %s", 1, "hello");
    ALWAYS_LOG("test %d %s", 1, "hello");

    Log_smbclient(NULL, LOG_LVL_DEBUG, "test msg from smbclient");
    Log_smbclient(NULL, LOG_LVL_WARNING, "test msg from smbclient");
    Log_smbclient(NULL, LOG_LVL_INFO, "test msg from smbclient");
    Log_smbclient(NULL, LOG_LVL_ERROR, "test msg from smbclient");
    Log_smbclient(NULL, LOG_LVL_TRACE, "test msg from smbclient");
    Log_smbclient(NULL, LOG_LVL_ALWAYS, "test msg from smbclient");
}

#endif //_DEBUG_