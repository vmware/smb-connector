/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#include <algorithm>

#include "base/Log.h"
#include "base/Error.h"
#include "Configuration.h"

Configuration Configuration::instance;

/*!
 * Constructor that initializes the configuration data to their default values
 */
Configuration::Configuration()
{
    setDefaultValues();
}

/*!
 * Destructor
 */
Configuration::~Configuration()
{
    //Destructor
}

/*!
 * Set default values.
 * Sets configuration values to expected defaults
 */
void Configuration::setDefaultValues()
{
    _table[C_OP_MODE] = DEFAULT_OP_MODE;
    _table[C_SOCK_NAME] = DEFAULT_SOCK_NAME;
    _table[C_LOG_LEVEL] = DEFAULT_LOG_LEVEL;
    _table[C_LOG_FILE] = DEFAULT_LOG_FILE;
    _table[C_OP_CODE] = DEFAULT_OP_CODE;
    _table[C_URL] = DEFAULT_URL;
    _table[C_USER_NAME] = DEFAULT_USER_NAME;
    _table[C_PASSWORD] = DEFAULT_PASSWORD;
    _table[C_WORK_GROUP] = DEFAULT_WORK_GROUP;
    _table[C_SHOW_ONLY_FOLDERS] = DEFAULT_SHOW_ONLY_FOLDERS;
    _table[C_SHOW_HIDDEN_FILES] = DEFAULT_SHOW_HIDDEN_FILES;
    _table[C_PAGE_SIZE] = DEFAULT_PAGE_SIZE;
    _table[C_BUFFER_SIZE] = DEFAULT_BUFFER_SIZE;
    _table[C_START_OFFSET] = DEFAULT_START_OFFSET;
    _table[C_END_OFFSET] = DEFAULT_END_OFFSET;
    _table[C_ACCEPT_QUEUE_SIZE] = DEFAULT_ACCEPT_QUEUE_SIZE;
    _table[C_UNIX_SOCK_BUFFER] = DEFAULT_UNIX_SOCK_BUFFER;
    _table[C_SMB_SOCK_READ_BUFFER] = DEFAULT_SMB_SOCK_READ_BUFFER;
    _table[C_SMB_SOCK_WRITE_BUFFER] = DEFAULT_SMB_SOCK_WRITE_BUFFER;
    _table[C_IDLE_TIMEOUT] = DEFAULT_IDLE_TIMEOUT;
    _table[C_SMB_CONF] = DEFAULT_SMB_CONF;
    _table[C_OUT_FILE] = DEFAULT_OUT_FILE;
    _table[C_CONF_FILE] = DEFAULT_CONF_FILE;
}

/*!
 * Reset.
 * Provided for testing.
 * Clears the contents of the configuration object and
 * sets them back to their default values.
 */
void Configuration::Reset()
{
    std::lock_guard<std::mutex> lock(_mtx);
    _table.clear();
    setDefaultValues();
}

/*!
 * Dump the configuration table to the logger for debugging
 */
void Configuration::DumpTable()
{
    CONFIG_MAP::iterator iter;
    std::lock_guard<std::mutex> lock(_mtx);

    for (iter = _table.begin(); iter != _table.end(); ++iter)
    {
        INFO_LOG("configuation:%s=%s", iter->first.c_str(), iter->second.c_str());
    }
}

/*!
 * Set the data of a configuration token to its new value. Create a new entry if old entry is not found.
 *
 * @param index - token to be set
 * @param value - value to be set
 */
void Configuration::Set(const char *index, const char *value)
{
    if (index == NULL)
    {
        ERROR_LOG("Configuration: Set: index == NULL");
        return;
    }

    if (value == NULL)
    {
        ERROR_LOG("Configuration: Set: value == NULL");
        return;
    }

    std::lock_guard<std::mutex> lock(_mtx);
    _table[index] = value;
}

/*!
 * Set the data of a configuration token to its new value. Create a new entry if old entry is not found.
 *
 * @param index - token to be set
 * @param value - integer value to be set
 */
void Configuration::Set(const char *index, int value)
{
    char value_s[16];
    snprintf(value_s, sizeof(value_s), "%d", value);
    Set(index, value_s);
}

/*!
 * Parse smb-connector.conf file
 * @return
 */
int Configuration::Parse()
{
    std::ifstream conf_file(_table[C_CONF_FILE]);
    std::string line;

    if(!conf_file.good())
    {
        ERROR_LOG("Configuration::Parse invalid configuration file, Kindly check if smb-connector.conf exists");
        return SMB_ERROR;
    }


    while(std::getline(conf_file, line))
    {
        if (line.c_str()[0] != '\n' && line.c_str()[0] != '\0' && line.c_str()[0] != '\r' && line.c_str()[0] != '#'
            && line.c_str()[0] != ';')
        {
            std::string token = line.substr(0, line.find(' '));
            std::string value = line.substr(line.find(' ')+1, line.length());
            //Remove whitespaces from value
            value.erase(std::remove(value.begin(), value.end(), ' '), value.end());
            std::lock_guard<std::mutex> lock(_mtx);
            _table[token] = value;
        }
    }

    conf_file.close();
    return SMB_SUCCESS;
}
