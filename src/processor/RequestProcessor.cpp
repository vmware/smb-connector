/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#include "RequestProcessor.h"
#include "base/Error.h"
#include "base/Log.h"

RequestProcessor *RequestProcessor::_instance = NULL;

/*!
 * Constructor
 */
RequestProcessor::RequestProcessor()
    : _request_id(""), _user_name(""), _password(""), _url(""), _work_group("")
{
    _sessionManager = NULL;
    _packet_creator = NULL;
    _packet_parser = NULL;
    _async_operation = NULL;
    _should_exit = false;
}

/*!
 * Destructor
 */
RequestProcessor::~RequestProcessor()
{
    delete _packet_creator;
    delete _packet_parser;
}

/*!
 * Get static instance
 * @return
 */
RequestProcessor *RequestProcessor::GetInstance()
{
    return RequestProcessor::_instance;
}

/*!
 * Set instance
 * @param instance
 */
void RequestProcessor::SetInstance(RequestProcessor *instance)
{
    _instance = instance;
}

/*!
 * Initialisation
 * @param id - request id
 * @return
 * SMB_SUCCESS    - Successful
 * Otherwise - Failed
 */
int RequestProcessor::Init(std::string &id)
{
    assert(id != "");
    DEBUG_LOG("RequestProcessor::Init");
    SmbClient::GetInstance()->Init();
    _request_id = id;
    return SMB_SUCCESS;
}

/*!
 * Cleanup
 */
void RequestProcessor::Quit()
{
    _should_exit = true;
    if (_async_operation)
    {
        _async_operation->join();
        FREE(_async_operation);
        _async_operation = NULL;
    }
    SmbClient::GetInstance()->Quit();
}

/*!
 * get user-name
 * @return
 */
const std::string &RequestProcessor::UserName() const
{
    return _user_name;
}

/*!
 * set user-name
 * @param user_name
 */
void RequestProcessor::SetUserName(const std::string &user_name)
{
    RequestProcessor::_user_name = user_name;
}

/*!
 * get password
 * @return
 */
const std::string &RequestProcessor::Password() const
{
    return _password;
}

/*!
 * set password
 * @param password
 */
void RequestProcessor::SetPassword(const std::string &password)
{
    RequestProcessor::_password = password;
}

/*!
 * get url
 * @return
 */
const std::string &RequestProcessor::Url() const
{
    return _url;
}

/*!
 * set-url
 * @param url
 */
void RequestProcessor::SetUrl(const std::string &url)
{
    RequestProcessor::_url = url;
}

/*!
 * get work-group
 * @return
 */
const std::string &RequestProcessor::WorkGroup() const
{
    return _work_group;
}

/*!
 * set work-group
 * @param work_group
 */
void RequestProcessor::SetWorkGroup(const std::string &work_group)
{
    RequestProcessor::_work_group = work_group;
}

/*!
 * get request-id
 * @return
 */
const std::string &RequestProcessor::RequestId() const
{
    return _request_id;
}

/*!
 * set request-id
 * @param id
 */
void RequestProcessor::SetRequestId(const std::string &id)
{
    RequestProcessor::_request_id = id;
}

/*!
 * get packet-creator instance
 * @return
 */
IPacketCreator *RequestProcessor::PacketCreator() const
{
    return _packet_creator;
}

/*!
 * get packet-parser instance
 * @return
 */
IPacketParser *RequestProcessor::PacketParser() const
{
    return _packet_parser;
}