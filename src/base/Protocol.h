/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#ifndef PROTOCOL_H_
#define PROTOCOL_H_

#define VERSION                     1

//Protocol codes

#define TEST_CONNECTION_INIT_REQ    1
#define TEST_CONNECTION_INIT_RESP   2
#define TEST_CONNECTION_ERROR_RESP  3

#define GET_STRUCTURE_INIT_REQ      11
#define GET_STRUCTURE_INIT_RESP     12
#define GET_STRUCTURE_END_RESP      13
#define GET_STRUCTURE_ERROR_RESP    14

#define UPLOAD_INIT_REQ             21
#define UPLOAD_INIT_RESP            22
#define UPLOAD_DATA_REQ             23
#define UPLOAD_ERROR                24
//#define UPLOAD_RESP_DATA_ERROR    25
#define UPLOAD_END_REQ              26
#define UPLOAD_END_RESP             27

#define DOWNLOAD_INIT_REQ           31
#define DOWNLOAD_INIT_RESP          32
#define DOWNLOAD_DATA_REQ           33
#define DOWNLOAD_DATA_RESP          34
#define DOWNLOAD_END_RESP           35
#define DOWNLOAD_ERROR              36

#define ADD_FOLDER_INIT_REQ         41
#define ADD_FOLDER_INIT_RESP        42
#define ADD_FOLDER_ERROR_RESP       43

#define DELETE_INIT_REQ             51
#define DELETE_INIT_RESP            52
#define DELETE_ERROR_RESP           53

const char *ProtocolCommand(int c);
#endif //PROTOCOL_H_



