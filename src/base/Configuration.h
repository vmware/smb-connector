/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#ifndef CONFIGRUATION_H_
#define CONFIGRUATION_H_

#include <mutex>
#include <map>
#include "Common.h"


typedef std::map<std::string, std::string> CONFIG_MAP;

class Configuration
{
private:
    static Configuration instance;

    CONFIG_MAP _table;
    std::mutex _mtx;

    void setDefaultValues();
    Configuration();
    virtual ~Configuration();

public:

    static Configuration &GetInstance()
    {
        return instance;
    }

    const char *operator[](const char *index)
    {
        std::lock_guard<std::mutex> lg(_mtx);
        return _table[index].c_str();
    }

    void Reset();
    void DumpTable();
    void Set(const char *index, const char *value);
    void Set(const char *index, int value);
    int Parse();
};

/* Unix socket settings */
#define C_ACCEPT_QUEUE_SIZE "accept"
#define C_UNIX_SOCK_BUFFER "unix_buffer"

#define C_SMB_CONF  "smb_conf"

/* SMB server socket settings
 * changing this settings is not recommended
 * If this is changed,
 * the smb.conf should also be changed
 */
#define C_SMB_SOCK_READ_BUFFER "smb_read_buffer"
#define C_SMB_SOCK_WRITE_BUFFER "smb_write_buffer"

/* smb-connector mode */
#define C_OP_MODE       "op_mode"
#define C_IDLE_TIMEOUT  "idle_timeout"

/* server mode settings */
#define C_SOCK_NAME     "sock_name"
#define C_LOG_FILE      "log_file"
#define C_LOG_LEVEL     "log_level"

/* client mode settings */
#define C_OP_CODE               "op_code"
#define C_URL                   "url"
#define C_USER_NAME             "user_name"
#define C_PASSWORD              "password"
#define C_WORK_GROUP            "workgroup"

//settings for open directory module
#define C_SHOW_ONLY_FOLDERS     "show_folder"
#define C_SHOW_HIDDEN_FILES     "show_hidden"
#define C_PAGE_SIZE             "page_size"

//buffer-queue size for download/upload operation
#define C_BUFFER_SIZE           "buff_size"

//settings for download
#define C_START_OFFSET          "start_offset"
#define C_END_OFFSET            "end_offset"

#define C_OUT_FILE              "output_file"

#define C_CONF_FILE             "conf_file"

#define C_USER                  "user"
#define C_GROUP                 "group"

////////////////////////////////////////////////////////////////////////////////////////
//                                                                                    //                                                                                        //
// Default value to be used by Configuration.cpp                                      //
// The macro only accepts string so no integer value allowed below or it will crash.  //
//                                                                                    //                                                                                       //
////////////////////////////////////////////////////////////////////////////////////////

#define DEFAULT_SMB_CONF    "/opt/airwatch/content-gateway/smb-connector/smb.conf"

#define DEFAULT_ACCEPT_QUEUE_SIZE   "1"
#define DEFAULT_UNIX_SOCK_BUFFER    "61440" //60KB

#define DEFAULT_SMB_SOCK_READ_BUFFER    "364544" //356KB
#define DEFAULT_SMB_SOCK_WRITE_BUFFER   "61440" //60KB

#define DEFAULT_OP_MODE             "1"
#define DEFAULT_IDLE_TIMEOUT        "300" //seconds

#define DEFAULT_SOCK_NAME           "smb-connector"
#define DEFAULT_LOG_FILE            "/var/log/airwatch/content-gateway/smb-connector/smbconnector.log"
#define DEFAULT_LOG_LEVEL           "0"

#define DEFAULT_OP_CODE             "0"
#define DEFAULT_URL                 ""
#define DEFAULT_USER_NAME           ""
#define DEFAULT_PASSWORD            ""
#define DEFAULT_WORK_GROUP          ""

#define DEFAULT_SHOW_ONLY_FOLDERS   "0"
#define DEFAULT_SHOW_HIDDEN_FILES   "1"
#define DEFAULT_PAGE_SIZE           "5"

#define DEFAULT_BUFFER_SIZE         "10"

#define DEFAULT_START_OFFSET        "0"
#define DEFAULT_END_OFFSET          "0"

#define DEFAULT_OUT_FILE            "out"

#define DEFAULT_CONF_FILE           "/opt/airwatch/content-gateway/smb-connector/smb-connector.conf"


#endif //CONFIGRUATION_H_
