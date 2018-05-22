/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#ifndef LOG_H_
#define LOG_H_

#include <time.h>
#include "base/Common.h"
#include "base/Constants.h"

#define LOG_LVL_DUMP        6
#define LOG_LVL_TRACE       5
#define LOG_LVL_DEBUG       4
#define LOG_LVL_INFO        3
#define LOG_LVL_WARNING     2
#define LOG_LVL_ERROR       1
#define LOG_LVL_NONE        0
#define LOG_LVL_ALWAYS      -1


//Samba logging as per README.Coding
#define SAMBA_DBG_ERR       0
#define SAMBA_DBG_WARNING   1
#define SAMBA_DBG_NOTICE    3
#define SAMBA_DBG_INFO      5
#define SAMBA_DBG_DEBUG     10

extern int logLevel;

void Log(int level, const char *format, ...);
void Log_smbclient(void *ptr, int level, const char *msg);
void generate_log_file_name();

#define DEBUG_LOG(...) do\
{if (logLevel >= LOG_LVL_DEBUG)    Log(LOG_LVL_DEBUG, __VA_ARGS__);} while (0)

#define INFO_LOG(...) do\
{if (logLevel >= LOG_LVL_INFO)     Log(LOG_LVL_INFO, __VA_ARGS__);} while (0)

#define WARNING_LOG(...) do\
{if (logLevel >= LOG_LVL_WARNING)  Log(LOG_LVL_WARNING, __VA_ARGS__);} while (0)

#define ERROR_LOG(...) do\
{if (logLevel >= LOG_LVL_ERROR)    Log(LOG_LVL_ERROR, __VA_ARGS__);} while (0)

#define ALWAYS_LOG(...) do\
{if (logLevel >= LOG_LVL_ALWAYS)     Log(LOG_LVL_ALWAYS, __VA_ARGS__);} while (0)

#if defined(_DEBUG_)
#define TRACE_LOG(...) do\
{if (logLevel >= LOG_LVL_TRACE)     Log(LOG_LVL_TRACE, __VA_ARGS__);} while (0)
#else
#define TRACE_LOG(...)
#endif

#endif //LOG_H_
