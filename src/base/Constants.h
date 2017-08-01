/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#ifndef CONSTANTS_H_
#define CONSTANTS_H_

#define HEADER_SIZE         16
#define LEN_SIZE            4
#define LENGTH_OFFSET       1
#define RESERVED_BYTES      11

#define MAX_LEN 1000

#define TRANSMIT_BUFFER_SIZE            2048
#define LONG_BUFFER_SIZE                1024
#define MEDIUM_BUFFER_SIZE              256
#define SHORT_BUFFER_SIZE               128
#define IDENT_BUFFER_SIZE               48

// File attributes
#define FILE_ATTRIBUTE_READONLY         0x0001L
#define FILE_ATTRIBUTE_HIDDEN           0x0002L
#define FILE_ATTRIBUTE_SYSTEM           0x0004L
#define FILE_ATTRIBUTE_VOLUME           0x0008L
#define FILE_ATTRIBUTE_DIRECTORY        0x0010L
#define FILE_ATTRIBUTE_ARCHIVE          0x0020L
#define FILE_ATTRIBUTE_DEVICE           0x0040L
#define FILE_ATTRIBUTE_NORMAL           0x0080L
#define FILE_ATTRIBUTE_TEMPORARY        0x0100L
#define FILE_ATTRIBUTE_SPARSE           0x0200L
#define FILE_ATTRIBUTE_REPARSE_POINT    0x0400L
#define FILE_ATTRIBUTE_COMPRESSED       0x0800L
#define FILE_ATTRIBUTE_OFFLINE          0x1000L
#define FILE_ATTRIBUTE_NONINDEXED       0x2000L
#define FILE_ATTRIBUTE_ENCRYPTED        0x4000L
#define FILE_ATTRIBUTE_ALL_MASK         0x7FFFL

/*Share attributes */
#define SMBC_WORKGROUP      1
#define SMBC_SERVER         2
#define SMBC_FILE_SHARE     3
#define SMBC_PRINTER_SHARE  4
#define SMBC_COMMS_SHARE    5
#define SMBC_IPC_SHARE      6
#define SMBC_DIR            7
#define SMBC_FILE           8
#define SMBC_LINK           9

#endif //CONSTANTS_H_
