/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#ifndef LOG4CPP_H_
#define LOG4CPP_H_

#include <log4cpp/Category.hh>
#include <log4cpp/Appender.hh>
#include <log4cpp/RollingFileAppender.hh>
#include <log4cpp/OstreamAppender.hh>
#include <log4cpp/Priority.hh>

#include "CustomLayout.h"

class Log4Cpp
{
private:
    log4cpp::Appender *_ostream_appender;
    log4cpp::Appender *_file_appender;
    log4cpp::Category *_category;

    int create_directory(const char *file_name);

public:
    Log4Cpp();
    ~Log4Cpp();

    int Init();
    void Write(int level, const char *format, va_list arg);
    void Write(int level, const char *msg);
    int Quit();
};


#endif //LOG4CPP_H_
