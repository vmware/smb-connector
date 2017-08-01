/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#include "processor/RequestProcessor.h"
#include "CustomLayout.h"

/*!
 * Appends request-id to log
 * @param event
 * @return
 * appended log
 */
std::string CustomLayout::format(const log4cpp::LoggingEvent &event)
{
    if (RequestProcessor::GetInstance() != NULL && RequestProcessor::GetInstance()->RequestId().length() > 0)
    {
        return "[" + RequestProcessor::GetInstance()->RequestId() + "] " + log4cpp::PatternLayout::format(event);
    }

    return "[ID_NOT_SET] " + log4cpp::PatternLayout::format(event);
}