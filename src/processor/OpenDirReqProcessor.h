/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#ifndef OPENDIR_REQUEST_PROCESSOR_H_
#define OPENDIR_REQUEST_PROCESSOR_H_

#include "RequestProcessor.h"

class OpenDirReqProcessor: public RequestProcessor
{

private:
    bool _show_only_folders;
    bool _show_hidden_files;
    bool _fetch_share;
    bool _is_directory;
    int _pageSize;

    int process_get_structure_req();
    int process_get_structure_req_resp();
    int process_get_structure_resp_end();
    int process_get_structure_req_error();
    int send_list_async();

public:

    OpenDirReqProcessor();
    virtual ~OpenDirReqProcessor();

    virtual int Init(std::string &request_id);
    virtual int ProcessRequest(Packet *request);
    struct file_info *GetFileInfo();
    struct stat *GetStat();
    struct smbc_dirent *GetDirent();

    /* getter/setter */
    bool ShowOnlyFolders() const;
    void SetShowOnlyFolders(bool show_only_folders);
    bool ShowHiddenFiles() const;
    void SetShowHiddenFiles(bool show_hidden_files);
    int PageSize() const;
    void SetPageSize(int _pageSize);
    bool IsDirectory() const;
    void SetIsDirectory(bool is_directory);
    bool FetchShare() const;
    void SetFetchShare(bool _fetch_share);

};


#endif //OPENDIR_REQUEST_PROCESSOR_H_
