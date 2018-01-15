/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */


#ifndef COMMON_H_
#define COMMON_H_

#include <stdio.h>
#include <iostream>
#include <fstream>
#include <string>
#include <string.h>
#include <malloc.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <stdarg.h>
#include <vector>
#include <arpa/inet.h>

//version
#define SMBCONNECTOR_VERSION "unknown"

#ifndef MIN
#define MIN(_a, _b)   (((_a) < (_b)) ? (_a) : (_b))
#endif

/*
 * Macros for memory allocate, deallocate
 */
#define ALLOCATE(TYPE, ...) new (std::nothrow)TYPE(__VA_ARGS__)
#define ALLOCATE_ARR(TYPE, SIZE) new (std::nothrow)TYPE[SIZE]
#define ALLOCATED(OBJ) OBJ?true:false

#define IS_NULL(OBJ) OBJ?false:true

/* delete only if !NULL */
#define FREE(OBJ) \
    if(OBJ) \
        delete OBJ

#define FREE_ARR(OBJ) \
    if(OBJ) \
        delete[] OBJ

/*!
 * 1 ms = 10^6 nano-seconds
 * 1 nano-second = 10^(-6) milli seconds
 *
 * 1 sec = 1000 milli-seconds
 */

#define NANO_TO_MS 1e-6 //Product of this with nano-seconds will get us ms
#define SEC_TO_MS 1e3 //Product of this with seconds will get us ms


#endif //COMMON_H_
