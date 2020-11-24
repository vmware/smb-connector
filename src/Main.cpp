/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#include <getopt.h>
#include <fstream>
#include <sys/prctl.h>
#include <dirent.h>

#ifdef _DEBUG_
#include <gtest/gtest.h>
#endif

#ifndef _DEBUG_
#include <execinfo.h>
#endif

#include "base/Constants.h"
#include "base/Log.h"
#include "base/Configuration.h"
#include "core/Server.h"
#include "core/Client.h"
#include "base/Log4Cpp.h"
#include "base/Error.h"

#define SMBCONNECTOR_USAGE \
"\t\t ## Configuration options ##\n" \
"\t\t-h, --help         - print this help information\n" \
"\t\t-v, --version      - version\n" \
"\t\t-l, --log_file     - set log file path (default: " DEFAULT_LOG_FILE ")\n" \
"\t\t-g, --log_level    - set logging level, supported values are from 1 to 6 (default: " DEFAULT_LOG_LEVEL ")\n" \
"\t\t-m, --mode         - smbconnector should run as server or client (default:server)\n" \
"\n"\
"\t ## Server mode options ##\n" \
"\t\t-s, --socket_name  - unix-domain socket to listen on\n" \
"\t\t-i, --idle_timeout - wait in seconds for request before application exit (default: " DEFAULT_IDLE_TIMEOUT " seconds)\n" \
"\t\t-c, --smb_conf     - set path for smb configuration file (default: " DEFAULT_SMB_CONF ")\n" \
"\n"\
"\t ## Client mode options ##\n" \
"\t\t-s, --socket_name  - unix-domain socket to connect to\n" \
"\t\t-o, --op_code      - operation to be performed 1(list directory), 2(download), 3(upload),\n \
\t\t\t\t     4(add-folder) 5(delete file/folder) 6(test-connection)\n" \
"\t\t-u, --url          - url to SMB server with file path appended\n" \
"\t\t-n, --user         - user-name\n" \
"\t\t-p, --password     - password\n" \
"\t\t-w, --workgroup    - workgroup\n" \
"\t\t-f, --show_folder  - should show only folders during list-dir operation\n" \
"\t\t-x, --is_kerberos  - enable kerberos authentication \n" \
"\t\t-d, --show_hidden  - should show hidden folders as well during list-dir operation\n" \
"\t\t-a, --page_size    - number of entries to be sent for list-directory operation (default: " DEFAULT_PAGE_SIZE ")\n" \
"\t\t-t, --start_offset - start offset for range file download (default: " DEFAULT_START_OFFSET" )\n" \
"\t\t-e, --end_offset   - end offset for range file download (default: File size)\n" \
"\t\t-q, --out_file     - output file to wrote download data for download operation\n" \
"\t\t-b, --buff_size    - buffer queue size for upload/download operation (default: " DEFAULT_BUFFER_SIZE ")\n" \


int should_exit = 0; //Setting this to 1 will exit all threads and bring application down
int logLevel = LOG_LVL_NONE;

Log4Cpp *logger = NULL;

static int caught_signal=0;
static char crash_file[64]={0};

static struct option long_options[] =
    {
        {"help",            no_argument,       0, 'h'},
        {"mode",            required_argument, 0, 'm'},
        {"socket_name",     required_argument, 0, 's'},
        {"op_code",         required_argument, 0, 'o'},
        {"log_file",        required_argument, 0, 'l'},
        {"log_level",       required_argument, 0, 'g'},
        {"url",             required_argument, 0, 'u'},
        {"user",            required_argument, 0, 'n'},
        {"password",        required_argument, 0, 'p'},
        {"workgroup",       required_argument, 0, 'w'},
        {"show_folder",     required_argument, 0, 'f'},
        {"show_hidden",     required_argument, 0, 'd'},
        {"page_size",       required_argument, 0, 'a'},
        {"start_offset",    required_argument, 0, 't'},
        {"end_offset",      required_argument, 0, 'e'},
        {"buff_size",       required_argument, 0, 'b'},
        {"idle_timeout",    required_argument, 0, 'i'},
        {"smb_conf",        required_argument, 0, 'c'},
        {"version",         no_argument,       0, 'v'},
        {"out_file",        required_argument, 0, 'q'},
        {"conf_file",       required_argument, 0, 'k'},
        {"is_kerberos",     no_argument,       0, 'x'},
        {0, 0, 0, 0}
    };


/*!
 * Does change user and group for the process
 *
 * @param user       - User name of running process
 * @param group      - Group name of user of running process
 */
void do_chuser(const char * user, const char * group)
{
    struct group * linux_group = NULL;
    struct passwd * linux_user = NULL;

    if (strlen(group) > 0)
    {
        linux_group = getgrnam(group);;
    }

    if (strlen(user) > 0)
    {
        linux_user = getpwnam(user);
    }

    if (linux_group)
    {
        if (setgid(linux_group->gr_gid) != 0)
        {
            ERROR_LOG("setgid failed with gid=%d", linux_group->gr_gid);
        }
        INFO_LOG("Set group to %s", linux_group->gr_name);
    }

    if (linux_user)
    {
        if (setuid(linux_user->pw_uid) != 0)
        {
            ERROR_LOG("setuid %d failed", linux_user->pw_uid);
        }
        INFO_LOG("Set user to %s", linux_user->pw_name);
    }
}

static void print_help()
{
    printf("Usage: smb-connector\n");
    printf(SMBCONNECTOR_USAGE);
}

static void process_args(int argc, char *argv[])
{
    Configuration &config = Configuration::GetInstance();
    while (true)
    {
        /* getopt_long stores the option index here. */
        int option_index = 0;
        int c = getopt_long(argc, argv, "hvm:s:o:l:g:u:n:p:w:f:d:a:t:e:b:i:c:q:x", long_options, &option_index);

        if (c == -1)
        {
            break;
        }

        switch (c)
        {
            case 'h':
                print_help();
                exit(0);
            case 'm':
                if (strcmp(optarg, "client") == 0)
                {
                    config.Set(C_OP_MODE, 0);
                }
                break;
            case 's':
                if (strlen(optarg) > MAX_LEN)
                {
                    ERROR_LOG("Too long socket name, maximum allowed size is 100");
                    exit(1);
                }
                config.Set(C_SOCK_NAME, optarg);
                break;
            case 'o':
                config.Set(C_OP_CODE, optarg);
                break;
            case 'l':
                if (strlen(optarg) > MAX_LEN)
                {
                    ERROR_LOG("Log file path is too long");
                    exit(1);
                }
                config.Set(C_LOG_FILE, optarg);
                break;
            case 'g':
                logLevel = atoi(optarg);
                config.Set(C_LOG_LEVEL, logLevel);
                break;
            case 'u':
                if (strlen(optarg) > MAX_LEN)
                {
                    ERROR_LOG("URL path is too long");
                    exit(1);
                }
                config.Set(C_URL, optarg);
                break;
            case 'n':
                if (strlen(optarg) > MAX_LEN)
                {
                    ERROR_LOG("User name is too long");
                    exit(1);
                }
                config.Set(C_USER_NAME, optarg);
                break;
            case 'p':
                if (strlen(optarg) > MAX_LEN)
                {
                    ERROR_LOG("Password is too long");
                    exit(1);
                }
                config.Set(C_PASSWORD, optarg);
                break;
            case 'w':
                if (strlen(optarg) > MAX_LEN)
                {
                    ERROR_LOG("Workgroup is too long");
                    exit(1);
                }
                config.Set(C_WORK_GROUP, optarg);
                break;
            case 'f':
                config.Set(C_SHOW_ONLY_FOLDERS, optarg);
                break;
            case 'd':
                config.Set(C_SHOW_HIDDEN_FILES, optarg);
                break;
            case 'x':
                config.Set(C_IS_KERBEROS, "1");
                break;
            case 'a':
                config.Set(C_PAGE_SIZE, optarg);
                break;
            case 't':
                config.Set(C_START_OFFSET, optarg);
                break;
            case 'e':
                config.Set(C_END_OFFSET, optarg);
                break;
            case 'b':
                config.Set(C_BUFFER_SIZE, optarg);
                break;
            case 'i':
                config.Set(C_IDLE_TIMEOUT, optarg);
                break;
            case 'c':
                config.Set(C_SMB_CONF, optarg);
                break;
            case 'v':
                printf("%s\n", SMBCONNECTOR_VERSION);
                exit(0);
            case 'q':
                config.Set(C_OUT_FILE, optarg);
                break;
            case 'k':
                config.Set(C_CONF_FILE, optarg);
                break;
            case '?':
                /* getopt_long already printed an error message. */
                exit(1);
            default:
                print_help();
                break;
        }
    }
}

#ifndef _DEBUG_
/*!
 * Callback function to catch Segmentation Fault
 * @param s - signal caught
 */
static void segv_handler(int s)
{
    /*
     * Dead lock might happen
     * when segmentation fault is originated due to logging.
     * Due to SEGV raised while executing logging statement
     * it would try to acquire log4cpp internal lock again
     * while writing to logs in this function which will result in dead lock.
     *
     * To avoid above mentioned dead lock
     * We won't write to the log file at all
     * https://wiki.sei.cmu.edu/confluence/display/c/SIG30-C.+Call+only+asynchronous-safe+functions+within+signal+handlers
     * Its a recommened practice to not call async-safe functions which might end us up in libc deadlock (__lll_lock_wait_private () from /lib64/libc.so.6 )
     * Here we will store the signal value and crash_report file name which will be logged later
     * once signal_handler function execution is done
     */

    should_exit = 1;
    caught_signal=s;

    // To generate a crash report, backtrace file
#define MAX_FRAMES 50
#define LOGNAME_FORMAT "crash_report_%Y_%m_%d_%H_%M_%S"
    void *stack_trace[MAX_FRAMES];
    int num_frames;
    num_frames = backtrace(stack_trace, MAX_FRAMES);

    time_t now = time(0);
    strftime(crash_file, sizeof(crash_file), LOGNAME_FORMAT, localtime(&now));	// not thread safe...

    int fd = -1;
    fd = open(crash_file, O_CREAT | O_RDWR, (mode_t) 0644);
    if(fd >0)
    {
        backtrace_symbols_fd(stack_trace, num_frames, fd);
        close(fd);
    }
}

#endif

static void my_handler(int s)
{
    should_exit = 1;
    caught_signal = s;
}

int main(int argc, char *argv[])
{

    Configuration &c = Configuration::GetInstance();
    prctl(PR_SET_PDEATHSIG, SIGHUP);
    prctl(PR_SET_PDEATHSIG, SIGTERM);
    prctl(PR_SET_PDEATHSIG, SIGINT);
    // Disable SIGPIPE signal that may terminate the smbconnector unintentionally
    signal(SIGPIPE, SIG_IGN);
    setbuf(stdout, static_cast<char *>(NULL));
    signal(SIGINT, static_cast<__sighandler_t>(my_handler));
#ifndef _DEBUG_
    signal(SIGSEGV, static_cast<__sighandler_t>(segv_handler));
#endif

    if(argc < 2)
    {
        print_help();
        exit(1);
    }


    logger = ALLOCATE(Log4Cpp);
    if (!ALLOCATED(logger))
    {
        ERROR_LOG("Log4Cpp allocation failed");
        return SMB_ERROR;
    }
#ifdef _DEBUG_
    if (argc >= 2 && (strcasecmp(argv[1], "unittest") == 0))
    {
        int ret = 0;
        logLevel = LOG_LVL_NONE;
        logger->Init();
        printf("Running unit test for smb-connector\n");
        testing::InitGoogleTest(&argc, argv);
        ret = RUN_ALL_TESTS();
        logger->Quit();
        FREE(logger);
        return ret;
    }
#endif
    process_args(argc, argv);
    generate_log_file_name();
    c.Parse();
    logLevel = atoi(c[C_LOG_LEVEL]);
    if (logger->Init() != SMB_SUCCESS)
    {
        printf("Logging failed");
    }
    ALWAYS_LOG("smb-connector version %s", SMBCONNECTOR_VERSION);

    ISmbConnector *smbConnector = NULL;
    if (argc < 2)
    {
        print_help();
        logger->Quit();
        FREE(logger);
        exit(1);
    }

    c.DumpTable();

    if (!atoi(c[C_OP_MODE]))
    {
        assert(strlen(c[C_URL]) > 0);
        assert(strlen(c[C_USER_NAME]) > 0);
        assert(strlen(c[C_PASSWORD]) > 0);

        smbConnector = ALLOCATE(Client);
        if (!ALLOCATED(smbConnector))
        {
            ERROR_LOG("client allocation failed");
            return SMB_ERROR;
        }
        smbConnector->Init(c[C_SOCK_NAME], atoi(c[C_OP_CODE]));
    }
    else
    {
        smbConnector = ALLOCATE(Server);
        if (!ALLOCATED(smbConnector))
        {
            ERROR_LOG("server allocation failed");
            return SMB_ERROR;
        }
        smbConnector->Init(c[C_SOCK_NAME]);
    }

    // change permission for domain-socket/log file to nobody
    struct passwd *linux_user = getpwnam(c[C_USER]);
    if(linux_user)
    {
        chown(c[C_SOCK_NAME],
              linux_user->pw_uid,
              linux_user->pw_gid);
        chown(c[C_LOG_FILE],
              linux_user->pw_uid,
              linux_user->pw_gid);
    }

    // drop user to nobody(default)
    do_chuser(c[C_USER], c[C_GROUP]);

    smbConnector->Runloop();

    smbConnector->Quit();
    FREE(smbConnector);

    if(caught_signal != 0)
    {
        //signal handler was called
        ALWAYS_LOG("Caught signal %d", caught_signal);
        if(caught_signal == SIGSEGV && strlen(crash_file) > 0)
        {
            ALWAYS_LOG("Crash report generated in %s", crash_file);
        }
    }

    logger->Quit();
    FREE(logger);
    return 0;
}
