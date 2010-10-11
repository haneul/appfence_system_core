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
#include <poll.h>
#include <errno.h>
#include <utils/Log.h>
#include <cutils/sockets.h>
#include <cutils/policyd.h>

#ifdef LOG_TAG
#undef LOG_TAG
#define LOG_TAG "policyd"
#endif

#define POLL_NFDS 2        /* Number of fds we need to poll/select on */
#define POLL_TIMEOUT -1    /* Negative means infinite timeout */
#define BACKLOG 12         /* No idea if this is appropriate... */
#define SECONDS 20
#define MAX_ERRORS 100     /* Maximum number of errors before we exit */

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

int main(int argc, char* argv[]) {
    int i, ret, err_count;
    int sockfd_settings, sockfd_app;
    nfds_t poll_nfds;
    int poll_timeout;
    struct pollfd poll_fds[POLL_NFDS];

    LOGW("phornyac: main: entered, argc=%d\n", argc);
    err_count = 0;
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
        exit(-1);
    }

    /**
     * Open the socket that the Settings app connects to to perform
     * policy database updates:
     */
    sockfd_settings = android_get_control_socket(POLICYD_UPDATESOCK);
    if (sockfd_settings < 0) {
        LOGW("phornyac: main: error number: %d", errno);
        LOGW("phornyac: main: could not open socket \"%s\", exiting",
                POLICYD_UPDATESOCK);
        exit(-1);
    }
    if (listen(sockfd_settings, 1) < 0) {
        LOGW("phornyac: main: error number: %d", errno);
        LOGW("phornyac: main: could not listen on socket \"%s\", exiting",
                POLICYD_UPDATESOCK);
        exit(-1);
    }
 
    /**
     * Open the socket that application VMs connect to to request 
     * policy checks:
     */
    sockfd_app = android_get_control_socket(POLICYD_SOCK);
    if (sockfd_app < 0) {
        LOGW("phornyac: main: error number: %d", errno);
        LOGW("phornyac: main: could not open socket \"%s\", exiting",
                POLICYD_SOCK);
        exit(-1);
    }
    if (listen(sockfd_app, BACKLOG) < 0) {
        LOGW("phornyac: main: error number: %d", errno);
        LOGW("phornyac: main: could not listen on socket \"%s\", exiting",
                POLICYD_SOCK);
        exit(-1);
    }
    
    /**
     * Set up the data structures for poll/select. We only care about
     * being able to accept (read) on our socket fds, so set events to
     * just POLLIN.
     *
     * In order to be notified of incoming connections on a socket, you can use
     * select(2) or poll(2).   A  _readable_  event
     * will  be  delivered when a new connection is attempted and you may
     * then call accept() to get a socket for that con‐
     * nection.  Alternatively, you can set the socket to deliver
     * SIGIO when activity occurs on a  socket;  see  socket(7)
     * for details.
     */
    poll_nfds = POLL_NFDS;
    poll_timeout = POLL_TIMEOUT;
    poll_fds[0].fd = sockfd_settings;
    poll_fds[1].fd = sockfd_app;
    poll_fds[0].events = POLLIN;
    poll_fds[1].events = POLLIN;
    if (1+1 != POLL_NFDS) {
        LOGE("phornyac: main: should have %d poll_fds, exiting",
                POLL_NFDS);
        exit(-1);
    }

    /**
     * Loop, accepting socket connections as they occur...
     */
    while (1) {
        if (err_count >= MAX_ERRORS) {
            LOGW("phornyac: main: reached max number of errors (%d), "
                    "exiting", err_count);
            exit(-1);
        }

        /* Poll on the fds we're waiting for connections from: */
        ret = poll((struct pollfd *)poll_fds, poll_nfds, poll_timeout);
        if (ret < 0) {
            LOGW("phornyac: main: error number: %d", errno);
            LOGW("phornyac: main: poll() returned %d, "
                    "looping again", ret);
            err_count++;
            continue;
        }
        else if (ret == 0) {
            LOGW("phornyac: main: poll() timed out... re-looping");
            err_count++;
            continue;
        }
        LOGW("phornyac: main: poll() returned %d fds ready to read",
                ret);

        /**
         * Handle the fds that are ready to be read:
         */
        for (i = 0; i < POLL_NFDS; i++) {
            if (poll_fds[i].revents & (POLLERR | POLLHUP | POLLNVAL)) {
                LOGW("phornyac: main: poll_fds[%d] has error 0x%X "
                        "(POLLERR=0x%X, POLLHUP=0x%X, POLLNVAL=0x%X), "
                        "continuing",
                        i, poll_fds[i].revents,
                        POLLERR, POLLHUP, POLLNVAL);
                err_count++;
                continue;
            } else if (poll_fds[i].revents & POLLIN) {
                LOGW("phornyac: main: poll_fds[%d] has event POLLIN",
                        i);
                switch(i) {
                case 0:  /* sockfd_settings */
                    ret = handle_connect_settings(sockfd_settings);
                    if (ret) {
                        LOGW("phornyac: main: handle_connect_settings() "
                                "returned %d, doing nothing",
                                ret);
                        err_count++;
                    }
                    break;
                case 1:  /* sockfd_app */
                    ret = handle_connect_app(sockfd_app);
                    if (ret) {
                        LOGW("phornyac: main: handle_connect_app() "
                                "returned %d, doing nothing",
                                ret);
                        err_count++;
                    }
                    break;
               default:
                    LOGW("phornyac: main: reached default case; "
                            "this is an error, doing nothing");
                    err_count++;
                }
            } else {
                /**
                 * poll() didn't get a POLLIN or an error for this fd,
                 * so do nothing.
                 */
                LOGW("phornyac: main: nothing to do for poll_fds[%d]",
                        i);
            }
        }
        LOGW("phornyac: main: reached end of while loop, err_count=%d",
                err_count);
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
 * Accepts a connection from the Settings app on the given socket
 * and handles the request/update...
 * Returns: 0 on success, negative on error.
 */
int handle_connect_settings(int sockfd) {
    LOGW("phornyac: handle_connect_settings: entered");

    LOGW("phornyac: handle_connect_settings: returning 0");
    return 0; 
}

/**
 * Accepts a connection from an application VM on the given socket
 * and handles it...
 * Returns: 0 on success, negative on error.
 */
int handle_connect_app(int sockfd) {
    int i, ret;
    struct sockaddr addr;
    socklen_t alen;
    int accept_fd;
    char sa_data[15];

    LOGW("phornyac: handle_connect_app: entered");

    /**
     * There should be a connection waiting to be accepted on
     * sockfd. TODO: set the sockets to non-blocking, so that if
     * for some reason there's an error here, we won't wait block
     * forever!
     *
     * "If no pending connections are present on the queue, and the
     *  socket is not marked as non-blocking,  accept()  blocks
     *  the  caller  until  a  connection  is present.  If the socket
     *  is marked non-blocking and no pending connections are
     *  present on the queue, accept() fails with the error EAGAIN or
     *  EWOULDBLOCK."
     */
    LOGW("phornyac: handle_connect_app: calling accept(%d)",
            sockfd);
    alen = sizeof(addr);
    ret = accept(sockfd, &addr, &alen);
    LOGW("phornyac: handle_connect_app: accept() returned %d", ret);
    if (ret < 0) {
        LOGW("phornyac: handle_connect_app: error number: %d",
                errno);
        LOGW("phornyac: handle_connect_app: could not accept "
                "socket connection, returning -1");
        return -1;
    } else {
        accept_fd = ret;
        for (i = 0; i < 14; i++)
            sa_data[i] = addr.sa_data[i];
        sa_data[14] = '\0';
        LOGW("phornyac: handle_connect_app: accepted new socket connection, "
                "accept_fd=%d, family=%d, data=%s",
                accept_fd, (int)addr.sa_family, sa_data);
    }
    
    /* Handle the accepted connection: */
    ret = handle_connection(accept_fd);
    if (ret) {
        LOGW("phornyac: handle_connect_app: handle_connection() "
                "returned %d, so closing accept_fd %d and "
                "returning -1", accept_fd, ret);
        close(accept_fd);
        return -1;
    }
    LOGW("phornyac: handle_connect_app: handle_connection() "
            "returned ok");

    /* Cleanup: */
    LOGW("phornyac: handle_connect_app: closing socket "
            "connection %d", accept_fd);
    close(accept_fd);

    LOGW("phornyac: handle_connect_app: returning 0");
    return 0; 
}

/**
 * Handles a connection on the given socket fd. ...
 * Returns: 0 on success, negative on error.
 */
int handle_connection(int sockfd) {
    LOGW("phornyac: handle_connection(): entered\n");
    int ret;
    int msg_size;
    policyd_msg msg_send;

    /* Construct the message: */
    strncpy(msg_send.msg, "Test message from server to client",
            POLICYD_MSG_SIZE);

    msg_size = sizeof(msg_send);
    LOGW("phornyac: handle_connection: calling write(%d) with msg=%s, "
            "msg_size=%d", sockfd, msg_send.msg, msg_size);
    ret = write(sockfd, &msg_send, msg_size);
    if (ret < 0) {
        LOGW("phornyac: handle_connection: error number: %d", errno);
        LOGW("phornyac: handle_connection: write() returned error, "
                "returning -1");
        return -1;
    }
    if (ret != msg_size) {
        LOGW("phornyac: handle_connection: error number: %d", errno);
        LOGW("phornyac: handle_connection: write() returned %d < %d, "
                "returning -2", ret, msg_size);
        return -2;
    }
    LOGW("phornyac: handle_connection: write() returned success");

    LOGW("phornyac: handle_connection(): returning 0");
    return 0;
}

