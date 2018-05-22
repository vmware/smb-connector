/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#ifndef SMBCLIENT_H_
#define SMBCLIENT_H_

#include <iostream>
#include <map>
#include <string>

#include "libsmbclient.h"


class SmbClient
{
private:
    SmbClient() : _ctx(NULL), _file(NULL) {}
    SmbClient(const SmbClient &instance);
    SmbClient &operator=(const SmbClient &instance);

    static SmbClient *_instance;

    /*SMB objects */
    SMBCCTX *_ctx;
    SMBCFILE *_file;

    std::string _server;
    std::string _work_group;
    std::string _username;
    std::string _password;

    struct stat _stat;
    unsigned int _start_offset;
    unsigned int _end_offset;
    size_t _read_bytes;

    int recursive_delete(SMBCFILE *file, std::string base_url);
    SMBCFILE *open_dir(std::string server);
    struct smbc_dirent *get_next_dirent(SMBCFILE *file);

public:
    static SmbClient *GetInstance();
    static void AuthCallback(const char *srv, const char *shr, char *wg, int wglen,
                             char *un, int unlen, char *pw, int pwlen);

    int Init();
    int CredentialsInit(std::string &server, std::string &workgroup, std::string &un, std::string &pass);

    void SetLogLevel();

    int OpenDir();
    struct file_info *GetNextFileInfo();
    struct smbc_dirent *GetNextDirent();
    int CloseDir();

    int OpenFile(int mode);
    struct stat *FileStat();
    int SetOffset(unsigned int start_offset, unsigned int end_offset);
    ssize_t Read(char *buffer, size_t len);
    int Write(char *buffer, size_t len);
    int CloseFile();

    int CreateDirectory();
    int Delete(bool &isDirectory);

    int DownloadInit();
    int UploadInit(const std::string &uid);

    int RestoreTmpFile(const std::string &uid);
    int DelTmpFile();

    int Quit();

    std::string &WorkGroup();
    std::string &User();
    std::string &Password();
};

#endif //SMBCLIENT_H_
