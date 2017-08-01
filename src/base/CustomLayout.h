/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#ifndef CUSTOM_LAYOUT_H_
#define CUSTOM_LAYOUT_H_

#include <log4cpp/PatternLayout.hh>
#include <log4cpp/LoggingEvent.hh>

class CustomLayout: public log4cpp::PatternLayout
{
public:
    virtual std::string format(const log4cpp::LoggingEvent &event);
};


#endif //CUSTOM_LAYOUT_H_
