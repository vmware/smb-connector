/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#include "Log4Cpp.h"
#include "base/Constants.h"
#include "base/Common.h"
#include "base/Error.h"
#include "base/Log.h"
#include "base/Configuration.h"

/*!
 * Constructor
 */
Log4Cpp::Log4Cpp()
{
    _ostream_appender = NULL;
    _file_appender = NULL;
    _category = NULL;
}

/*!
 * Destructor
 */
Log4Cpp::~Log4Cpp()
{
    //Destructor
}

/*!
 * Creates the log directory if its missing
 * @param file_name
 * @return
 * SMB_SUCCESS - On successful creation
 * Otherwise - error
 */
int Log4Cpp::create_directory(const char *file_name)
{
    /* create directory if not exists */
    char path[MAX_LEN];
    memset(path, 0, MAX_LEN);
    strncpy(path, file_name, sizeof(path) - 1);

    char *tmp = NULL;
    tmp = path + strlen(path);
    while (*tmp != '/' && tmp > path)
    {
        tmp--;
    }

    if (tmp == path)
    {
        return SMB_SUCCESS;
    }

    *tmp = '\0';
    struct stat st = {0};
    if (stat(path, &st) == -1)
    {
        create_directory(path);
        if (mkdir(path, 0777) != 0)
        {
            return SMB_ERROR;
        }
    }

    return SMB_SUCCESS;
}

/*!
 * Initialise Log4CPP object for logging
 * @return
 * SMB_SUCCESS - On successful creation
 * Otherwise - error
 */
int Log4Cpp::Init()
{

    Configuration &c = Configuration::GetInstance();
    if (create_directory(c[C_LOG_FILE]) != SMB_SUCCESS)
    {
        printf("Cannot create log file\n");
        return SMB_ERROR;
    }

    CustomLayout *ostream_layout = new CustomLayout();
    ostream_layout->setConversionPattern("%5r %t %5p: %m%n");

    CustomLayout *file_layout = new CustomLayout();
    file_layout->setConversionPattern("%d{%Y-%m-%d %H:%M:%S.%l} %t %5p: %m%n");

    _ostream_appender = new log4cpp::OstreamAppender("console", &std::cout);
    _file_appender = new log4cpp::RollingFileAppender("file", c[C_LOG_FILE], 20 * 1024 * 1024, 10, false, 00644);
    _ostream_appender->setLayout(ostream_layout);
    _file_appender->setLayout(file_layout);

    _category = &log4cpp::Category::getInstance("main_log");
    _category->setPriority(log4cpp::Priority::DEBUG);
    _category->setAdditivity(false);

    _category->addAppender(_ostream_appender);
    _category->addAppender(_file_appender);

    return SMB_SUCCESS;

}

/*!
 * Dumps log to console as well as log file
 * @param level - logging level
 * @param format - format
 * @param arg - arguments
 * SMB_SUCCESS - On successful creation
 * Otherwise - error
 */
void Log4Cpp::Write(int level, const char *format, va_list arg)
{
    if (level == LOG_LVL_ERROR)
    {
        _category->logva(log4cpp::Priority::ERROR, format, arg);
    }
    else if (level == LOG_LVL_WARNING)
    {
        _category->logva(log4cpp::Priority::WARN, format, arg);
    }
    else if (level == LOG_LVL_INFO)
    {
        _category->logva(log4cpp::Priority::INFO, format, arg);
    }
    else if (level == LOG_LVL_DEBUG)
    {
        _category->logva(log4cpp::Priority::DEBUG, format, arg);
    }
    else if (level == LOG_LVL_TRACE)
    {
        _category->logva(log4cpp::Priority::DEBUG, format, arg);
    }
    else if (level == LOG_LVL_DUMP)
    {
        _category->logva(log4cpp::Priority::DEBUG, format, arg);
    }
    else if (level == LOG_LVL_ALWAYS)
    {
        _category->logva(log4cpp::Priority::INFO, format, arg);
    }
}

/*!
 * Logs string message (Used to log smbclient logs)
 * @param level - log level
 * @param msg - log message
 */
void Log4Cpp::Write(int level, const char *msg)
{
    if (level == SAMBA_DBG_ERR)
    {
        _category->log(log4cpp::Priority::ERROR, msg);
    }
    else if (level == SAMBA_DBG_WARNING)
    {
        _category->log(log4cpp::Priority::WARN, msg);
    }
    else if (level == SAMBA_DBG_INFO)
    {
        _category->log(log4cpp::Priority::INFO, msg);
    }
    else if (level == SAMBA_DBG_DEBUG)
    {
        _category->log(log4cpp::Priority::DEBUG, msg);
    }
    else if (level == SAMBA_DBG_NOTICE)
    {
        _category->log(log4cpp::Priority::NOTICE, msg);
    }
}

/*!
 * Cleanup
 * @return
 * SMB_SUCCESS - Sucess
 */
int Log4Cpp::Quit()
{
    log4cpp::Category::shutdown();
    return SMB_SUCCESS;
}