/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#include "Log.h"
#include "Log4Cpp.h"
#include "Configuration.h"

extern int logLevel;

extern Log4Cpp *logger;

/*!
 * Directs log line to log4cpp impl
 * @param level
 * @param format
 * @param ...
 */
void Log(int level, const char *format, ...)
{
    if (!logger)
    {
        return;
    }

    if (level > logLevel)
    {
        return;
    }

    {
        va_list argptr;
        va_start(argptr, format);
        logger->Write(level, format, argptr);
        va_end(argptr);
    }
}

/*!
 * Callback to capture logs from libsmbclient
 * @param ptr - NULL(unused)
 * @param level - log-level
 * @param msg - Log message
 */
void Log_smbclient(void *ptr, int level, const char *msg)
{
    if (!logger)
    {
        return;
    }

    if (level > logLevel)
    {
        return;
    }

    {
        logger->Write(level, msg);
    }
}

/*!
 * Used to generate log file name based on request-id
 */
void generate_log_file_name()
{
    Configuration &c = Configuration::GetInstance();
    std::string log_file(DEFAULT_LOG_FILE);
    std::string tmp_sock_name = "";

    if (strcmp(log_file.c_str(), c[C_LOG_FILE]) != 0)
    {
        //Log file set by user from command
        return;
    }
    std::string sock_name(c[C_SOCK_NAME]);
    if (sock_name.find_last_of("/") == std::string::npos)
    {
        tmp_sock_name = sock_name + ".log";
    }
    else
    {
        tmp_sock_name = sock_name.substr(sock_name.find_last_of("/") + 1, sock_name.length()) + ".log";
    }
    log_file.replace(log_file.find_last_of("smbconnector.log") - strlen("smbconnector.log") + 1,
                     tmp_sock_name.length() > strlen("smbconnector.log") ? tmp_sock_name.length() : strlen(
                         "smbconnector.log"), tmp_sock_name);
    c.Set(C_LOG_FILE, log_file.c_str());
}