/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <utils/Log.h>
#include <cutils/sockets.h>
//#include "cutils/log.h"
#include "policyd.h"

#define SOCKETNAME "policyd"
#define BACKLOG 12  /* No idea if this is appropriate... */

void fatal(const char *msg) {
    fprintf(stderr, msg);
    LOG(LOG_ERROR, "policyd", msg);
    exit(-1);
}

void usage() {
    fatal(
        "Usage: policyd\n"
        "\n"
        "...\n"
        "...\n");
}

#define SECONDS 20

int main(int argc, char* argv[]) {
    int i, ret;
    struct sockaddr addr;
    socklen_t alen;
    int fd, s;
    char sa_data[15];

    LOGW("phornyac: main: entered, argc=%d\n", argc);
    LOGW("phornyac: main: sleeping for %d secs to wait for logging to start\n",
            SECONDS);
    sleep(SECONDS);
    for (i = 0; i < argc; i++) {
        LOGW("phornyac: main: argv[%d]=%s\n", i, argv[i]);
    }

//TODO:
#if 0
    /* set as high priority, and protect from OOM killer */
    setpriority(PRIO_PROCESS, 0, -20);
    protect_from_oom_killer();
    get_time(&now);
#endif

    /* Initialize the policy database: */
    ret = initialize_policydb();
    if (ret) {
        LOGW("phornyac: main: initialize_policydb() returned %d, exiting",
                ret);
        exit(1);
    }

    s = android_get_control_socket(SOCKETNAME);
    if (s < 0) {
        //LOGW("phornyac: main: error message: %s", sys_errlist[errno]);
        LOGW("phornyac: main: error number: %d", errno);
        LOGW("phornyac: main: could not open socket \"%s\", exiting",
                SOCKETNAME);
        exit(1);
    }
    if (listen(s, BACKLOG) < 0) {
        //LOGW("phornyac: main: error message: %s", sys_errlist[errno]);
        LOGW("phornyac: main: error number: %d", errno);
        LOGW("phornyac: main: could not listen on socket \"%s\", exiting",
                SOCKETNAME);
        exit(2);
    }
    
    alen = sizeof(addr);

    /**
     * Loop, accepting socket connections as they occur...
     */
    while (1) {
        /* "If no pending connections are present on the queue, and the
         *  socket is not marked as non-blocking,  accept()  blocks
         *  the  caller  until  a  connection  is present.  If the socket
         *  is marked non-blocking and no pending connections are
         *  present on the queue, accept() fails with the error EAGAIN or
         *  EWOULDBLOCK."
         */
        LOGW("phornyac: main: calling accept()");
        fd = accept(s, &addr, &alen);
        if (fd < 0) {
            //LOGW("phornyac: main: error message: %s", sys_errlist[errno]);
            LOGW("phornyac: main: error number: %d", errno);
            LOGW("phornyac: main: could not accept socket connection, "
                    "looping again");
            continue;
        } else {
            for (i = 0; i < 14; i++)
                sa_data[i] = addr.sa_data[i];
            sa_data[14] = '\0';
            LOGW("phornyac: main: accepted new socket connection, "
                    "family=%d, data=%s",
                    (int)addr.sa_family, sa_data);
        }

        /* Handle the accepted connection: */
        ret = handle_connection(s);
        if (ret) {
            LOGW("phornyac: main: handle_connection() returned %d, "
                    "but doing nothing about it.",
                    ret);
        }

        LOGW("phornyac: main: closing socket connection and looping again");
        close(fd);
    }
    
    LOGW("phornyac: reached end of policyd main, returning 0\n");
    return 0;
}

/**
 * Initializes the policy database: ...
 * Returns: 0 on success, negative on error.
 */
int initialize_policydb() {
    LOGW("phornyac: initialize_policydb(): entered\n");

    LOGW("phornyac: initialize_policydb(): returning 0\n");
    return 0;
}

/**
 * Handles a connection on the given socket fd. ...
 * Returns: 0 on success, negative on error.
 */
int handle_connection(int sock_fd) {
    LOGW("phornyac: handle_connection(): entered\n");

    LOGW("phornyac: handle_connection(): returning 0\n");
    return 0;
}

#if 0
void parent(const char *tag, int seg_fault_on_exit, int parent_read) {
    int status;
    char buffer[4096];

    int a = 0;  // start index of unprocessed data
    int b = 0;  // end index of unprocessed data
    int sz;
    while ((sz = read(parent_read, &buffer[b], sizeof(buffer) - 1 - b)) > 0) {

        sz += b;
        // Log one line at a time
        for (b = 0; b < sz; b++) {
            if (buffer[b] == '\r') {
                buffer[b] = '\0';
            } else if (buffer[b] == '\n') {
                buffer[b] = '\0';
                LOG(LOG_INFO, tag, &buffer[a]);
                a = b + 1;
            }
        }

        if (a == 0 && b == sizeof(buffer) - 1) {
            // buffer is full, flush
            buffer[b] = '\0';
            LOG(LOG_INFO, tag, &buffer[a]);
            b = 0;
        } else if (a != b) {
            // Keep left-overs
            b -= a;
            memmove(buffer, &buffer[a], b);
            a = 0;
        } else {
            a = 0;
            b = 0;
        }

    }
    // Flush remaining data
    if (a != b) {
        buffer[b] = '\0';
        LOG(LOG_INFO, tag, &buffer[a]);
    }
    status = 0xAAAA;
    if (wait(&status) != -1) {  // Wait for child
        if (WIFEXITED(status))
            LOG(LOG_INFO, "logwrapper", "%s terminated by exit(%d)", tag,
                    WEXITSTATUS(status));
        else if (WIFSIGNALED(status))
            LOG(LOG_INFO, "logwrapper", "%s terminated by signal %d", tag,
                    WTERMSIG(status));
        else if (WIFSTOPPED(status))
            LOG(LOG_INFO, "logwrapper", "%s stopped by signal %d", tag,
                    WSTOPSIG(status));
    } else
        LOG(LOG_INFO, "logwrapper", "%s wait() failed: %s (%d)", tag,
                strerror(errno), errno);
    if (seg_fault_on_exit)
        *(int *)status = 0;  // causes SIGSEGV with fault_address = status
}

void child(int argc, char* argv[]) {
    // create null terminated argv_child array
    char* argv_child[argc + 1];
    memcpy(argv_child, argv, argc * sizeof(char *));
    argv_child[argc] = NULL;

    if (execvp(argv_child[0], argv_child)) {
        LOG(LOG_ERROR, "logwrapper",
            "executing %s failed: %s\n", argv_child[0], strerror(errno));
        exit(-1);
    }
}

int main(int argc, char* argv[]) {
    pid_t pid;
    int seg_fault_on_exit = 0;

    int parent_ptty;
    int child_ptty;
    char *child_devname = NULL;

    if (argc < 2) {
        usage();
    }

    if (strncmp(argv[1], "-d", 2) == 0) {
        seg_fault_on_exit = 1;
        argc--;
        argv++;
    }

    if (argc < 2) {
        usage();
    }

    /* Use ptty instead of socketpair so that STDOUT is not buffered */
    parent_ptty = open("/dev/ptmx", O_RDWR);
    if (parent_ptty < 0) {
        fatal("Cannot create parent ptty\n");
    }

    if (grantpt(parent_ptty) || unlockpt(parent_ptty) ||
            ((child_devname = (char*)ptsname(parent_ptty)) == 0)) {
        fatal("Problem with /dev/ptmx\n");
    }

    pid = fork();
    if (pid < 0) {
        fatal("Failed to fork\n");
    } else if (pid == 0) {
        child_ptty = open(child_devname, O_RDWR);
        if (child_ptty < 0) {
            fatal("Problem with child ptty\n");
        }

        // redirect stdout and stderr
        close(parent_ptty);
        dup2(child_ptty, 1);
        dup2(child_ptty, 2);
        close(child_ptty);

        child(argc - 1, &argv[1]);

    } else {
        // switch user and group to "log"
        // this may fail if we are not root, 
        // but in that case switching user/group is unnecessary 
        setgid(AID_LOG);
        setuid(AID_LOG);

        parent(argv[1], seg_fault_on_exit, parent_ptty);
    }

    return 0;
}
#endif
