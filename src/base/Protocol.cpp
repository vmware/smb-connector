/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#include "Protocol.h"

/*!
 * Returns Command as string
 * @param c
 * @return
 */
const char *ProtocolCommand(int c)
{
    switch (c)
    {
        case GET_STRUCTURE_INIT_REQ:
            return "GET_STRUCTURE_INIT_REQ";
        case GET_STRUCTURE_INIT_RESP:
            return "GET_STRUCTURE_INIT_RESP";
        case GET_STRUCTURE_END_RESP:
            return "GET_STRUCTURE_END_RESP";
        case GET_STRUCTURE_ERROR_RESP:
            return "GET_STRUCTURE_ERROR_RESP";

        case UPLOAD_INIT_REQ:
            return "UPLOAD_INIT_REQ";
        case UPLOAD_INIT_RESP:
            return "UPLOAD_INIT_RESP";
        case UPLOAD_DATA_REQ:
            return "UPLOAD_DATA_REQ";
        case UPLOAD_ERROR:
            return "UPLOAD_ERROR";
        case UPLOAD_END_REQ:
            return "UPLOAD_END_REQ";
        case UPLOAD_END_RESP:
            return "UPLOAD_END_RESP";

        case DOWNLOAD_INIT_REQ:
            return "DOWNLOAD_INIT_REQ";
        case DOWNLOAD_INIT_RESP:
            return "DOWNLOAD_INIT_RESP";
        case DOWNLOAD_DATA_REQ:
            return "DOWNLOAD_DATA_REQ";
        case DOWNLOAD_DATA_RESP:
            return "DOWNLOAD_DATA_RESP";
        case DOWNLOAD_END_RESP:
            return "DOWNLOAD_END_RESP";
        case DOWNLOAD_ERROR:
            return "DOWNLOAD_ERROR";

        case ADD_FOLDER_INIT_REQ:
            return "ADD_FOLDER_INIT_REQ";
        case ADD_FOLDER_INIT_RESP:
            return "ADD_FOLDER_INIT_RESP";
        case ADD_FOLDER_ERROR_RESP:
            return "ADD_FOLDER_ERROR_RESP";

        case DELETE_INIT_REQ:
            return "DELETE_INIT_REQ";
        case DELETE_INIT_RESP:
            return "DELETE_INIT_RESP";
        case DELETE_ERROR_RESP:
            return "DELETE_ERROR_RESP";

        case TEST_CONNECTION_INIT_REQ:
            return "TEST_CONNECTION_INIT_REQ";
        case TEST_CONNECTION_INIT_RESP:
            return "TEST_CONNECTION_INIT_RESP";
        case TEST_CONNECTION_ERROR_RESP:
            return "TEST_CONNECTION_ERROR_RESP";

        default:
            return "INVALID_COMMAND";
    }
}