/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#ifndef ERROR_H_
#define ERROR_H_

#include <string>

#ifdef __cplusplus
extern "C" {
#endif

#define SMB_ERROR               -11
#define SMB_INIT_FAILED         -12
#define SMB_OPEN_FAILED         -13
#define SMB_INVALID_SERVER      -14
#define SMB_AGAIN               -15
#define SMB_RESET               -16
#define SMB_EOF                 -17
#define SMB_NOT_FOUND           -18
#define SMB_TIMEOUT             -19
#define SMB_ALLOCATION_FAILED   -20
#define SMB_FILE_CREATE_FAILED  -21

#define SMB_INVALID_PACKET      -28
#define SMB_SUCCESS              0
#define SMB_CREATE_SUCCESS       1

const char *GetError(int code);

#ifdef __cplusplus
}
#endif

#endif //ERROR_H_
