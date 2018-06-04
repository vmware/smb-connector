/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#include <memory.h>

#include "SmbClient.h"
#include "base/Log.h"
#include "base/Error.h"
#include "base/Configuration.h"

SmbClient *SmbClient::_instance = NULL;

extern int should_exit;

/*!
 * Performs a recursive delete for a directory
 * @param file - base directory
 * @param base_url - path to base directory
 * @return
 * SMB_SUCCESS - success
 * Otherwise - Failure
 */
int SmbClient::recursive_delete(SMBCFILE *file, std::string base_url)
{
    struct smbc_dirent *dirent = NULL;

    while ((dirent = get_next_dirent(file)) != NULL)
    {
        if (strcasecmp(dirent->name, ".") != 0 && strcasecmp(dirent->name, "..") != 0)
        {
            std::string b_url = base_url + "/" + std::string(dirent->name, dirent->namelen);
            if (dirent->smbc_type & SMBC_DIR)
            {
                SMBCFILE *file_r = open_dir(b_url);
                if (file_r != NULL)
                {
                    recursive_delete(file_r, b_url);
                }
                else
                {
                    WARNING_LOG("SmbClient::recursive_delete opening '%s' file failed, error: %d, error-string: %s",
                                b_url.c_str(), errno, strerror(errno));
                }
            }

            DEBUG_LOG("SmbClient::recursive_delete Deleting '%s' file", b_url.c_str());
            std::string url = "smb://" + b_url;
            if (smbc_getFunctionUnlink(_ctx)(_ctx, url.c_str()) != SMB_SUCCESS)
            {
                WARNING_LOG("SmbClient::recursive_delete Deleting '%s' file failed, error: %d, error-string: %s",
                            b_url.c_str(), errno, strerror(errno));
            }

        }
    }

    return SMB_SUCCESS;
}

/*!
 * OpenDir for given path
 * @param server - path to file to open
 * @return
 * SMBCFILE - Success
 * NULL - Failure
 */
SMBCFILE *SmbClient::open_dir(std::string server)
{
    DEBUG_LOG("SmbClient::open_dir(string, string");
    std::string url = "smb://" + server;

    SMBCFILE *file = smbc_getFunctionOpendir(_ctx)(_ctx, url.c_str());

    if (file == NULL)
    {
        DEBUG_LOG("SmbClient::open_dir failed");
        return NULL;
    }

    return file;
}

/*!
 * Get the list of file inside a directory
 * @param file - directory to be traversed
 * @return
 * smbc_dirent - entry from list
 * NULL - when list traversal is finished
 */
struct smbc_dirent *SmbClient::get_next_dirent(SMBCFILE *file)
{

    DEBUG_LOG("SmbClient::get_next_dirent(file)");
    assert(file != NULL);
    return smbc_getFunctionReaddir(_ctx)(_ctx, file);
}

/*!
 * get instance
 * @return
 */
SmbClient *SmbClient::GetInstance()
{
    if (SmbClient::_instance == NULL)
    {
        SmbClient::_instance = new SmbClient();
    }
    return SmbClient::_instance;
}

/*!
 * callback from libsmbclient to fetch workgroup, user-name, password
 * @param srv - server address
 * @param shr - share
 * @param wg - workgroup
 * @param wglen - maxlen for workgroup
 * @param un - username
 * @param unlen - maxlen for user-name
 * @param pw - password
 * @param pwlen - maxlen for password
 */
void SmbClient::AuthCallback(const char *srv, const char *shr, char *wg, int wglen,
                             char *un, int unlen, char *pw, int pwlen)
{

    DEBUG_LOG("Inside AuthCallback %s server, %s share", srv, shr);

    if ((SmbClient::GetInstance()->WorkGroup().length() > (unsigned int) wglen) ||
        (SmbClient::GetInstance()->User().length() > (unsigned int) unlen) ||
        (SmbClient::GetInstance()->Password().length() > (unsigned int) pwlen))
    {
        ERROR_LOG("Too long workgroup or username or password");
        return;
    }
    else
    {
        memset(wg, 0, wglen);
        memset(un, 0, unlen);
        memset(pw, 0, pwlen);
    }

    memcpy(wg, SmbClient::GetInstance()->WorkGroup().c_str(), SmbClient::GetInstance()->WorkGroup().length());
    memcpy(un, SmbClient::GetInstance()->User().c_str(), SmbClient::GetInstance()->User().length());
    memcpy(pw, SmbClient::GetInstance()->Password().c_str(), SmbClient::GetInstance()->Password().length());
}

/*!
 *
 * Initialise the libsmbclient library objects
 * @return
 *      SMB_SUCCESS - Successful
 *      SMB_ALLOCATION_FAILED - Context allocation failed
 *      SMB_INIT_FAILED - ctx init failed
 */
int SmbClient::Init()
{
    DEBUG_LOG("SmbClient::Init, log_level %d", logLevel);
    Configuration &c = Configuration::GetInstance();
    _ctx = smbc_new_context();

    if (_ctx == NULL)
    {
        DEBUG_LOG("SmbClient::Init smbc_new_context failed");
        return SMB_ALLOCATION_FAILED;
    }
    SetLogLevel();
    smbc_setLogCallback(_ctx, Log_smbclient);
    smbc_setConfiguration(_ctx, c[C_SMB_CONF]);
    SMBCCTX *tmp = smbc_init_context(_ctx);

    if (_ctx != tmp)
    {
        DEBUG_LOG("SmbClient::Init smbc_init_context failed");
        return SMB_INIT_FAILED;
    }

    smbc_setFunctionAuthData(_ctx, AuthCallback);
    return SMB_SUCCESS;
}

/*!
 * Initialises the credentials
 * @param server - server address
 * @param share - share
 * @param workgroup - workgroup
 * @param un - user-name
 * @param pass - password
 * @return
 *      SMB_SUCCESS - Successful
 *      Otherwise - failed
 */
int SmbClient::CredentialsInit(std::string &server, std::string &workgroup, std::string &un, std::string &pass)
{
    DEBUG_LOG("SmbClient::CredentialsInit");
    INFO_LOG("%s %s %s", server.c_str(), workgroup.c_str(), un.c_str());
    _server = server;
    _work_group = workgroup;
    _username = un;
    _password = pass;

    if(_work_group.length() == 0)
    {
        _work_group = smbc_getWorkgroup(_ctx);
        INFO_LOG("Empty workgroup, picked up from smb.conf file, new workgroup:%s", _work_group.c_str());
    }

    return SMB_SUCCESS;
}

/*!
 * Convert log level from smb-connector to that
 * of libsmbclient log level and set the same
 * for libsmbclient
 */
void SmbClient::SetLogLevel()
{
    extern int logLevel;

    if (logLevel == LOG_LVL_ERROR)
    {
        smbc_setDebug(_ctx, SAMBA_DBG_ERR);
    }
    else if (logLevel == LOG_LVL_WARNING)
    {
        smbc_setDebug(_ctx, SAMBA_DBG_WARNING);
    }
    else if (logLevel == LOG_LVL_INFO)
    {
        smbc_setDebug(_ctx, SAMBA_DBG_INFO);
    }
    else if (logLevel == LOG_LVL_DEBUG)
    {
        smbc_setDebug(_ctx, SAMBA_DBG_DEBUG);
    }
    else
    {
        smbc_setDebug(_ctx, SAMBA_DBG_ERR);
    }
}

/*!
 *
 * Creates a connection to SMB server
 * and fetches the files/folders list from  share
 * @param server - SMB server url
 * @param share - Share name
 * @param workgroup - WorkGroup for user
 * @param un - User Name
 * @param pass - Password
 *
 * @return
 *      SMB_SUCCESS - Successful
 *      SMB_OPEN_FAILED - smbc_open failed
 */
int SmbClient::OpenDir()
{
    DEBUG_LOG("SmbClient::OpenDir");
    std::string url = "smb://" + _server;

    _file = smbc_getFunctionOpendir(_ctx)(_ctx, url.c_str());

    if (_file == NULL)
    {
        WARNING_LOG("SmbClient::OpenDir failed");
        return SMB_ERROR;
    }

    return SMB_SUCCESS;
}

/*!
 *
 * Returns next file info from linked list after open call
 *
 * @return
 *      file_info - Structure containing file information
 *      NULL - Whole list is traversed
 */
struct file_info *SmbClient::GetNextFileInfo()
{
    DEBUG_LOG("SmbClient::GetNextFileInfo");
    if (_file == NULL)
    {
        ERROR_LOG("SmbClient::GetNextFileInfo failed");
        return NULL;
    }
    return smbc_getFunctionReaddirPlus(_ctx)(_ctx, _file);
}

/*!
 *
 * Returns next share info from linked list after open call
 *
 * @return
 *      smbc_dirent - Structure containing share information
 *      NULL - Whole list is traversed
 */
struct smbc_dirent *SmbClient::GetNextDirent()
{
    DEBUG_LOG("SmbClient::GetNextDirent");
    assert(_file != NULL);
    return smbc_getFunctionReaddir(_ctx)(_ctx, _file);
}

/*!
 * Close the directory
 * @return
 *      SMB_SUCCESS - Successful
 *      Otherwise - failure
 */
int SmbClient::CloseDir()
{
    DEBUG_LOG("SmbClient::CloseDir");
    int ret = -1;
    if (_file != NULL)
    {
        ret = smbc_getFunctionClosedir(_ctx)(_ctx, _file);
    }
    _file = NULL;
    return ret;
}

/*!
 * Open the file with attributes
 * @param mode - file open mode
 * @return
 *      SMB_SUCCESS - Successful
 *      Otherwise - failure
 */
int SmbClient::OpenFile(int mode)
{
    DEBUG_LOG("SmbClient::OpenFile");
    assert(_ctx != NULL);
    assert(_file == NULL);

    assert(_server != "");
    assert(_work_group != "");
    assert(_username != "");
    assert(_password != "");

    int ret = SMB_ERROR;

    std::string url = "smb://" + _server;

    _file = smbc_getFunctionOpen(_ctx)(_ctx, url.c_str(), mode, 0);

    if (_file == NULL)
    {
        ERROR_LOG("SmbClient::OpenFile Open failed");
        return SMB_OPEN_FAILED;
    }

    /* store file stat */
    ret = smbc_getFunctionFstat(_ctx)(_ctx, _file, &_stat);

    if (ret != 0)
    {
        ERROR_LOG("SmbClient::OpenFile Error getting Stat");
        return SMB_OPEN_FAILED;
    }

    return SMB_SUCCESS;
}

/*!
 * get the attributes of open file
 * @return
 * attributes structure
 */
struct stat *SmbClient::FileStat()
{
    DEBUG_LOG("SmbClient::FileStat");
    return &_stat;
}

/*!
 * set the start, end_offset for download operation
 * @param start_offset
 * @param end_offset
 * @return
 *      SMB_SUCCESS - Successful
 *      Otherwise - failure
 */
int SmbClient::SetOffset(unsigned int start_offset, unsigned int end_offset)
{
    DEBUG_LOG("SmbClient::SetOffset");
    _start_offset = start_offset;
    _end_offset = end_offset;

    int ret;
    /* set the offset */
    if (_start_offset > 0)
    {
        ret = smbc_getFunctionLseek(_ctx)(_ctx, _file, _start_offset, SEEK_SET);
        if (ret < 0)
        {
            ERROR_LOG("SmbClient::SetOffset lseek failed");
            return SMB_ERROR;
        }

        _read_bytes += _start_offset;
    }

    return SMB_SUCCESS;
}

/*!
 * Read data fom file in buffer
 * @param buffer - output buffer
 * @param len - max len
 * @return
 *      number of bytes read (<0 for error)
 */
ssize_t SmbClient::Read(char *buffer, size_t len)
{
    DEBUG_LOG("SmbClient::Read");
    ssize_t ret;
    assert(_ctx != NULL);
    assert(_file != NULL);
    if ((_end_offset - _read_bytes) < 0)
    {
        DEBUG_LOG("SmbClient::Read All bytes read");
        return SMB_SUCCESS;
    }
    ret = smbc_getFunctionRead(_ctx)(_ctx, _file, buffer, len);

    if (ret < 0)
    {
        WARNING_LOG("SmbClient::Read Read error");
        return ret;
    }

    _read_bytes += ret;

    /* Over-read the data */
    if (_read_bytes > _end_offset)
    {
        _read_bytes -= ret;
        ret = _end_offset - _read_bytes + 1;
        _read_bytes += (_end_offset - _read_bytes) + 1;
    }

    return ret;
}

/*!
 * Write the data to file
 * @param buffer - buffer containing data to be written
 * @param len - length of buffer
 * @return
 *      number of bytes written (<0 for error)
 */
int SmbClient::Write(char *buffer, size_t len)
{
    DEBUG_LOG("SmbClient::Write");
    int ret;

    if (_ctx == NULL || _file == NULL)
    {
        WARNING_LOG("SmbClient::Write, File already closed");
        return SMB_SUCCESS;
    }

    ret = smbc_getFunctionWrite(_ctx)(_ctx, _file, buffer, len);

    if (ret < 0)
    {
        ERROR_LOG("SmbClient::Write Write error");
    }

    return ret;
}

/*!
 * Close the file
 * @return
 *      SMB_SUCCESS - Successful
 *      Otherwise - failure
 */
int SmbClient::CloseFile()
{
    DEBUG_LOG("SmbClient::CloseFile");
    if (_ctx == NULL || _file == NULL)
    {
        DEBUG_LOG("CloseFile, File already closed");
        return SMB_SUCCESS;
    }

    int ret = smbc_getFunctionClose(_ctx)(_ctx, _file);

    if (ret != 0)
    {
        WARNING_LOG("SmbClient::CloseFile Close file error");
    }

    _file = NULL;
    return ret;
}

/*!
 * Create folder
 * @return
 *      SMB_SUCCESS - Successful
 *      Otherwise - failure
 */
int SmbClient::CreateDirectory()
{
    DEBUG_LOG("SmbClient::CreateDirectory");
    std::string url = "smb://" + _server;

    int ret = smbc_getFunctionMkdir(_ctx)(_ctx, url.c_str(), S_IRWXU | S_IRWXG | S_IRWXO); //default mode

    if (ret != SMB_SUCCESS)
    {
        ERROR_LOG("SmbClient::CreateDirectory failed Error: %s", strerror(errno));
        return ret;
    }

    ret = smbc_getFunctionStat(_ctx)(_ctx, url.c_str(), &_stat);

    return ret;
}

/*!
 * Deletes a file/folder
 * @param isDirectory - sets to true accordingly
 * @return
 *      SMB_SUCCESS - Successful
 *      Otherwise - failure
 */
int SmbClient::Delete(bool &isDirectory)
{
    DEBUG_LOG("SmbClient::Delete");
    std::string url = "smb://" + _server;
    int ret;
    /*
     * let's try to open it as directory
     * And delete all files recursively
     */

    DEBUG_LOG("Deleting '%s' file", _server.c_str());
    if (OpenDir() == SMB_SUCCESS)
    {
        /*
         * definitely a directory
         * Lets remove content recusively
         * We will ignore error from recursive delete
         * There might be permission issue when all files cannot be deleted
         */
        isDirectory = true;
        recursive_delete(_file, _server);

        ret = smbc_getFunctionRmdir(_ctx)(_ctx, url.c_str());
        if (ret != SMB_SUCCESS)
        {
            return SMB_ERROR;
        }
        else
        {
            return ret;
        }
    }

    /* try to remove it as file */
    ret = smbc_getFunctionUnlink(_ctx)(_ctx, url.c_str());

    if (ret == SMB_SUCCESS)
    {
        isDirectory = false;
        return ret;
    }
    else
    {
        ERROR_LOG("SmbClient::Delete Delete failed");
        return ret;
    }

    return SMB_SUCCESS;
}

/*!
 * initialise download module variables and
 * open the file for download in RD_ONLY mode
 * @return
 *      SMB_SUCCESS - Successful
 *      Otherwise - failure
 */
int SmbClient::DownloadInit()
{
    DEBUG_LOG("SmbClient::DownloadInit");
    _start_offset = 0;
    _end_offset = 0;
    _read_bytes = 0;

    return OpenFile(O_RDONLY);
}

/*!
 * Create directory recursivley for non-existing directory
 * @param path - Complete path where the directory should be created
 * @return
 * SMB_SUCCESS - Success
 * Otherwise - Error
 */
int SmbClient::create_directory(std::string path)
{
    /*!
     * We will try to create the child folder first
     * If it fails with error ENOENT, we try to create parent folder
     * and then try to create child folder again
     * If that also fails, we bail out and propagate the error to caller
     */

    int ret = smbc_getFunctionMkdir(_ctx)(_ctx, path.c_str(), 0);
    if(ret != SMB_SUCCESS && errno == ENOENT)
    {
        //Child folder creation failed since parent folder is not created
        //Try to create parent folder first
        if(path.find_last_of('/') != std::string::npos)
        {
            if(create_directory(path.substr(0, path.find_last_of('/'))) != SMB_SUCCESS)
            {
                ERROR_LOG("SmbClient::create_directory parent folder creation failed with error %d", errno);
                return SMB_ERROR;
            }
        }
        else
        {
            ERROR_LOG("SmbClient::create_directory reached end of path, cannot create folder");
            return SMB_ERROR;
        }

        //Parent folder is created
        // lets try to create the child folder again now
        if (smbc_getFunctionMkdir(_ctx)(_ctx, path.c_str(), 0) == SMB_SUCCESS)
        {
            DEBUG_LOG("Smbclient::create_directory Directory %s created", path.c_str());
            return SMB_SUCCESS;
        }
        else
        {
            ERROR_LOG("SmbClient::create_directory failed for %s with error %d:%d", path.c_str(), ret, errno);
            return SMB_ERROR;
        }
    }
    else if(ret != SMB_SUCCESS && errno == EEXIST) //Child folder already exists, we can break out here
    {
        DEBUG_LOG("SmbClient::create_directory Directory already exists %s", path.c_str());
        return SMB_SUCCESS;
    }
    else if(ret == SMB_SUCCESS) //Child folder is created in recursive call, we can break out here
    {
        DEBUG_LOG("Smbclient::create_directory Directory %s created", path.c_str());
        return SMB_SUCCESS;
    }
    else //Some unknown error occurred, propagate the error to caller
    {
        ERROR_LOG("SmbClient::create_directory cannot create directory %s, error:%d", path.c_str(), ret);
        return SMB_ERROR;
    }

    return SMB_ERROR;

}

/*!
 * Initialises upload module variables and
 * creates, truncates and open file for upload
 * @return
 *      SMB_SUCCESS - Successful
 *      Otherwise - failure
 */
int SmbClient::UploadInit(const std::string &uid)
{
    DEBUG_LOG("SmbClient::UploadInit");

    /*
     * Create directory recursively if it doesn't exists
     */

    if(_server.find_last_of('/') != std::string::npos)
    {
        if (create_directory("smb://" + _server.substr(0, _server.find_last_of('/'))) == SMB_SUCCESS)
        {
            DEBUG_LOG("SmbClient::UploadInit Recursive folder exists/created for %s", _server.c_str());
        }
        else
        {
            WARNING_LOG("SmbClient::UploadInit Recursive folder create failed for %s", _server.c_str());
        }
    }

    _server += "." + uid;
    _server += ".smbconnector";
    return OpenFile(O_CREAT | O_RDWR | O_TRUNC);
}

/*!
 * Restore the file from file_name.tmp to file_name
 * to be used when upload fails
 * @return
 *      SMB_SUCCESS - Successful
 *      Otherwise - failure
 */
int SmbClient::RestoreTmpFile(const std::string &uid)
{
    DEBUG_LOG("SmbClient::RestoreTmpFile");
    std::string furl = "smb://" + _server;
    std::string burl = furl.substr(0, furl.find_last_of(uid) - uid.length());

    int ret = smbc_getFunctionRename(_ctx)(_ctx, furl.c_str(), _ctx, burl.c_str());

    DEBUG_LOG("SmbClient::RestoreTmpFile File restored returns %d", ret);
    return SMB_SUCCESS;
}

/*!
 * Deletes backed-up file when upload is successful
 * @return
 *      SMB_SUCCESS - Successful
 *      Otherwise - failure
 */
int SmbClient::DelTmpFile()
{
    DEBUG_LOG("SmbClient::DelTmpFile %s", _server.c_str());
    if (_ctx == NULL || _file == NULL)
    {
        DEBUG_LOG("DelTmpFile, File already deleted");
        return SMB_SUCCESS;
    }
    std::string url = "smb://" + _server;
    if (CloseFile() != SMB_SUCCESS)
    {
        WARNING_LOG("SmbClient::DelTmpFile File close failed");
        return SMB_ERROR;
    }
    int ret = smbc_getFunctionUnlink(_ctx)(_ctx, url.c_str());
    if (ret != SMB_SUCCESS)
    {
        int err = errno;
        WARNING_LOG("SmbClient::DelTmpFile Deleting tmp failed errno=%d, errstring=%s", err, strerror(err));
        return ret;
    }
    return SMB_SUCCESS;
}

/*!
 *
 * De-initialise the libsmbclient library
 *
 * @return
 *      SMB_SUCCESS - Success
 */
int SmbClient::Quit()
{
    DEBUG_LOG("SmbClient::Quit");
    int ret = 0;
    for (int i = 0; i < 10; ++i)
    {
        ret = smbc_free_context(_ctx, 1);
        if (ret == 0)
        {
            break;
        }
    }
    _ctx = NULL;
    _file = NULL;
    return SMB_SUCCESS;
}

/*!
 *
 * Get the Workgroup
 */
std::string &SmbClient::WorkGroup()
{
    return _work_group;
}

/*!
 *
 * Get the User name
 */
std::string &SmbClient::User()
{
    return _username;
}

/*!
 *
 * Get the Password
 */
std::string &SmbClient::Password()
{
    return _password;
}
