/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#include "Error.h"

/*!
 * Converts error-code to string
 * @param err_code
 * @return
 * error-string
 */
const char *GetError(int err_code)
{
    switch (err_code)
    {
        case SMB_SUCCESS:
            return "SMB_SUCCESS";
        case SMB_ERROR:
            return "SMB_ERROR";
        case SMB_INVALID_PACKET:
            return "SMB_INVALID_PACKET";
        default:
            return "NONE";
    }
}