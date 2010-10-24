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
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
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
#define MAX_ERRORS 100     /* Maximum number of errors before we exit */
#define SECONDS 20
#undef DELAY_START

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
 * Handles a request from the connection to the Settings application
 * on the given socket fd. First read()s the message from the socket,
 * then write()s a message back.
 * Returns: 0 on success, negative on error.
 */
int handle_request_settings(int sockfd) {
    int ret;
    int msg_size;
    policyd_msg msg_send;

    LOGW("phornyac: handle_request_settings: entered");

    //XXX: this gets called when the socket is ready for READING;
    //  need to update it to read() first, then write()!

    /* Construct the message: */
    strncpy(msg_send.msg, "Test message from server to Settings app",
            POLICYD_MSG_SIZE);

    msg_size = sizeof(msg_send);
    LOGW("phornyac: handle_request_settings: calling write(%d) with msg=%s, "
            "msg_size=%d", sockfd, msg_send.msg, msg_size);
    ret = write(sockfd, &msg_send, msg_size);
    if (ret < 0) {
        LOGW("phornyac: handle_request_settings: error number: %d", errno);
        LOGW("phornyac: handle_request_settings: write() returned error, "
                "returning -1");
        return -1;
    }
    if (ret != msg_size) {
        LOGW("phornyac: handle_request_settings: error number: %d", errno);
        LOGW("phornyac: handle_request_settings: write() returned %d < %d, "
                "returning -2", ret, msg_size);
        return -2;
    }
    LOGW("phornyac: handle_request_settings: write() returned success");

    LOGW("phornyac: handle_request_settings: returning 0");
    return 0;
}

/**
 * Handles a connection from an application VM on the
 * given socket fd. First read()s the message from the socket,
 * then write()s a message back.
 * Returns: 0 on success, negative on error.
 */
int handle_request_app(int sockfd) {
    LOGW("phornyac: handle_request_app: entered\n");
    int ret;
    int msg_size;
    policyd_msg msg_send;

    //XXX: this gets called when the socket is ready for READING;
    //  need to update it to read() first, then write()!

    /* Construct the message: */
    strncpy(msg_send.msg, "Test message from server to client app",
            POLICYD_MSG_SIZE);

    msg_size = sizeof(msg_send);
    LOGW("phornyac: handle_request_app: calling write(%d) with msg=%s, "
            "msg_size=%d", sockfd, msg_send.msg, msg_size);
    ret = write(sockfd, &msg_send, msg_size);
    if (ret < 0) {
        LOGW("phornyac: handle_request_app: error number: %d (EPIPE=%d)",
                errno, EPIPE);
        LOGW("phornyac: handle_request_app: write() returned error, "
                "returning -1");
        return -1;
    }
    if (ret != msg_size) {
        LOGW("phornyac: handle_request_app: error number: %d", errno);
        LOGW("phornyac: handle_request_app: write() returned %d < %d, "
                "returning -2", ret, msg_size);
        return -2;
    }
    LOGW("phornyac: handle_request_app: write() returned success");

    LOGW("phornyac: handle_request_app: returning 0");
    return 0;
}

/**
 * Generic function to accept a connection on the given socket.
 * NOTE: on success, it is the caller's job to close the socket fd!
 * Returns: the fd of the accepted connection, or negative on error.
 */
int accept_new(int sockfd) {
    int i, ret;
    struct sockaddr addr;
    socklen_t alen;
    int accept_fd;
    char sa_data[15];

    LOGW("phornyac: accept_new: entered");

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
    LOGW("phornyac: accept_new: calling accept(%d)",
            sockfd);
    alen = sizeof(addr);
    ret = accept(sockfd, &addr, &alen);
    LOGW("phornyac: accept_new: accept() returned %d", ret);
    if (ret < 0) {
        LOGW("phornyac: accept_new: error number: %d",
                errno);
        LOGW("phornyac: accept_new: could not accept "
                "socket connection, returning -1");
        return -1;
    } else {
        accept_fd = ret;
        for (i = 0; i < 14; i++)
            sa_data[i] = addr.sa_data[i];
        sa_data[14] = '\0';
        LOGW("phornyac: accept_new: accepted new socket connection, "
                "accept_fd=%d, family=%d, data=%s",
                accept_fd, (int)addr.sa_family, sa_data);
    }

    LOGW("phornyac: accept_new: returning accepted fd %d",
            accept_fd);
    return accept_fd;
}

/**
 * Accepts a connection from the Settings app on the given socket
 * and handles the request/update...
 * Returns: the accepted socket fd on success, negative on error.
 */
int accept_settings(int sockfd) {
    int i, ret;
    int accepted_fd;

    LOGW("phornyac: accept_settings: entered");

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
    LOGW("phornyac: accept_settings: calling accept(%d)",
            sockfd);
    ret = accept_new(sockfd);
    if (ret < 0) {
        LOGW("phornyac: accept_settings: accept_new() returned "
               "error %d, returning -1", ret);
        return -1;
    } else {
        accepted_fd = ret;
        LOGW("phornyac: accept_settings: accept_new() returned "
               "accepted_fd=%d", accepted_fd);
    }

    LOGW("phornyac: accept_settings: returning accepted_fd=%d",
            accepted_fd);
    return accepted_fd;

#if 0
    //TODO: unreachable code!!!
    /* Handle the accepted connection: */
    ret = handle_request_settings(accepted_fd);
    if (ret) {
        LOGW("phornyac: accept_settings: handle_request_settings() "
                "returned %d, so closing accepted_fd %d and "
                "returning -1", accepted_fd, ret);
        close(accepted_fd);
        return -1;
    }
    LOGW("phornyac: accept_settings: handle_request_settings() "
            "returned ok");

    /* Cleanup: */
    LOGW("phornyac: accept_settings: closing socket "
            "connection %d", accepted_fd);
    close(accepted_fd);

    LOGW("phornyac: accept_settings: returning 0");
    return 0;
#endif
}

/**
 * Accepts a connection from an application VM on the given socket
 * and handles it...
 * Returns: the accepted socket fd on success, negative on error.
 */
int accept_app(int sockfd) {
    int i, ret;
    int accepted_fd;

    LOGW("phornyac: accept_app: entered");

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
    LOGW("phornyac: accept_app: calling accept_new(%d)",
            sockfd);
    ret = accept_new(sockfd);
    if (ret < 0) {
        LOGW("phornyac: accept_app: accept_new() returned "
               "error %d, returning -1", ret);
        return -1;
    } else {
        accepted_fd = ret;
        LOGW("phornyac: accept_app: accept_new() returned "
               "accepted_fd=%d", accepted_fd);
    }

    LOGW("phornyac: accept_app: returning accepted_fd=%d",
            accepted_fd);
    return accepted_fd;

#if 0
    //TODO: unreachable code!!!
    /* Handle the accepted connection: */
    ret = handle_request_app(accepted_fd);
    if (ret) {
        LOGW("phornyac: accept_app: handle_request_app() "
                "returned %d, so closing accepted_fd %d and "
                "returning -1", accepted_fd, ret);
        close(accepted_fd);
        return -1;
    }
    LOGW("phornyac: accept_app: handle_request_app() "
            "returned ok");

    /* Cleanup: */
    LOGW("phornyac: accept_app: closing socket "
            "connection %d", accepted_fd);
    close(accepted_fd);

    LOGW("phornyac: accept_app: returning 0");
    return 0;
#endif
}

/**
 * Main loop for policy daemon server: accepts connections on given
 * socket fds, and ...
 *
 * Returns: 0 on success, -1 on error.
 */
int accept_loop(int sockfd_settings, int sockfd_app) {
    int i, ret, err_count;
    int nfds;
    int accepted_settings_fd = -1;
    fd_set rd_set, wr_set, er_set;
    fd_set rd_ret, wr_ret, er_ret;
    struct timeval timeout;
    #undef max
    #define max(x,y) ((x) > (y) ? (x) : (y))

    LOGW("phornyac: accept_loop: entered");
    LOGW("phornyac: accept_loop: sockfd_settings=%d, sockfd_app=%d",
            sockfd_settings, sockfd_app);
    err_count = 0;
    
    /**
     * Set up the data structures for select; we use select because its fd_set
     * stuff is easier to manipulate that poll's list of poll_fd structs. 
     * "A readable event will be delivered when a new connection is
     *  attempted and you may then call accept() to get a socket for that
     *  connection."
     * So, we care about the read set for the initial connections to the
     * sockets that policyd opens; for connected connections from apps
     * (including the Settings app), we care about the read set when apps
     * are going to send us requests (by write()ing on their end), and
     * then we care about the write set when apps are listening for our
     * response.
     */
    FD_ZERO(&rd_set);
    FD_ZERO(&rd_ret);
    FD_ZERO(&wr_set);
    FD_ZERO(&wr_ret);
    FD_ZERO(&er_set);
    FD_ZERO(&er_ret);
    FD_SET(sockfd_settings, &rd_set);
    FD_SET(sockfd_app, &rd_set);
    nfds = max(sockfd_settings, sockfd_app);
      /* "an integer one more than the maximum of any file descriptor
       *  in any of the sets"; we'll add the 1 later. */

    /**
     * Loop, accepting socket connections as they occur...
     */
    while (1) {
        if (err_count >= MAX_ERRORS) {
            LOGW("phornyac: accept_loop: reached max number of errors (%d), "
                    "returning -1", err_count);
            return -1;
        }

        /**
         * Call select() to wait for connections or requests on our fds.
         * Block indefinitely by passing NULL for the timeval. Since select()
         * modifies the input sets, copy them first before passing them in.
         * "On success, select() returns the total number of file descriptors
         *  still present in the file descriptor sets. If select() timed out,
         *  then the return value will be zero. ... A return value of -1
         *  indicates an error, with errno being set appropriately."
         */
        rd_ret = rd_set;
        wr_ret = wr_set;
        er_ret = er_set;
        ///* timeout value must be updated before every call: */
        //timeout.tv_sec = 1;   /* seconds */
        //timeout.tv_usec = 0;  /* microseconds */
        LOGW("phornyac: accept_loop: sockfd_settings=%d, "
                "sockfd_app=%d, accepted_settings_fd=%d",
                sockfd_settings, sockfd_app, accepted_settings_fd);
        LOGW("phornyac: accept_loop: calling select() with nfds=%d and "
                "NULL timeout", nfds);
        ret = select(nfds + 1, &rd_ret, &wr_ret, &er_ret, NULL);
        ////XXX: shouldn't need to use a timeout!!!
        //LOGW("phornyac: accept_loop: calling select() with nfds=%d and "
        //        "non-NULL timeout", nfds);
        //ret = select(nfds + 1, &rd_ret, &wr_ret, &er_ret, &timeout);
        if (ret < 0) {
            LOGW("phornyac: accept_loop: error number %d (EINTR is %d)",
                    errno, EINTR);
            LOGW("phornyac: accept_loop: select() returned %d, "
                    "looping again", ret);
            err_count++;
            continue;
        }
        else if (ret == 0) {
            LOGW("phornyac: accept_loop: select() timed out, re-looping");
            err_count++;
            continue;
        }
        LOGW("phornyac: accept_loop: select() returned %d fds still in "
                "the fd sets", ret);

        /**
         * Handle the fds that are ready to be read. To avoid tracking a
         * list of all the fds we're using, we just loop from 0 to nfds,
         * which we maintain as the maximum fd value in the sets. This is
         * pretty inefficient, but oh well.
         */
        LOGW("phornyac: accept_loop: starting for loop up to nfds=%d",
                nfds);
        for (i = 0; i <= nfds; i++) {
            if (FD_ISSET(i, &rd_ret)) {
                LOGW("phornyac: accept_loop: fd %d is ready for reading",
                        i);
                if (i == sockfd_settings) {  /* New connection from Settings */
                    LOGW("phornyac: accept_loop: new connection from Settings");
                    /* Accept connection:*/
                    ret = accept_settings(sockfd_settings);
                    if (ret < 0) {
                        LOGW("phornyac: accept_loop: accept_settings() "
                                "returned error %d, doing nothing",
                                ret);
                        err_count++;
                    }
                    /* Store new fd, add it to read set, and adjust nfds: */
                    LOGW("phornyac: accept_loop: accept_settings() returned "
                            "fd %d, adding to rd_set", ret);
                    accepted_settings_fd = ret;
                    FD_SET(ret, &rd_set);
                    nfds = max(nfds, ret);
                } else if (i == sockfd_app) {  /* New connection from app */
                    LOGW("phornyac: accept_loop: new connection from app");
                    /* Accept connection:*/
                    ret = accept_app(sockfd_app);
                    if (ret < 0) {
                        LOGW("phornyac: accept_loop: accept_app() "
                                "returned error %d, doing nothing",
                                ret);
                        err_count++;
                    }
                    /* Add new fd to read set and adjust nfds: */
                    LOGW("phornyac: accept_loop: accept_app() returned "
                            "fd %d, adding to rd_set", ret);
                    FD_SET(ret, &rd_set);
                    nfds = max(nfds, ret);
                } else if (i == accepted_settings_fd) {
                    /* Existing connection from Settings */
                    LOGW("phornyac: accept_loop: existing connection from "
                            "Settings");
                    /* Handle the request: */
                    ret = handle_request_settings(i);
                    if (ret) {
                        LOGW("phornyac: accept_loop: handle_request_settings() "
                                "returned error %d, closing its fd %d",
                                ret, i);
                        close(i);
                        FD_CLR(i, &rd_set);
                        err_count++;
                    }
                    LOGW("phornyac: accept_loop: handle_request_settings() "
                            "returned ok");
                } else {  /* Existing connection from app */
                    LOGW("phornyac: accept_loop: existing connection from "
                            "app");
                    /* Handle the request: */
                    ret = handle_request_app(i);
                    if (ret) {
                        LOGW("phornyac: accept_loop: handle_request_app() "
                                "returned error %d, closing its fd %d",
                                ret, i);
                        close(i);
                        FD_CLR(i, &rd_set);
                        err_count++;
                    }
                    LOGW("phornyac: accept_loop: handle_request_app() "
                            "returned ok");
                }
            } else {
                /* Nothing ready for reading on this fd */
                LOGW("phornyac: accept_loop: nothing to do for fd %d",
                        i);
            }
            //TODO: check wr_ret?
            //TODO: check er_ret?
            //TODO: when do we close fds???
        } //for()

        //XXX: when do we exit the while loop??
        LOGW("phornyac: accept_loop: reached end of while loop, "
                "looping again");

    } //while()
    LOGW("phornyac: accept_loop: finished (why?), returning 0");
    return 0;
}

#if 0
/**
 * Main loop for policy daemon server: accepts connections on given
 * socket fds, and ...
 * XXX: this is the original implementation, using poll()...
 *
 * Returns: 0 on success, -1 on error.
 */
int accept_loop_poll(int sockfd_settings, int sockfd_app) {
    int i, ret, err_count;
    nfds_t poll_nfds;
    int poll_timeout;
    struct pollfd poll_fds[POLL_NFDS];

    LOGW("phornyac: accept_loop: entered");
    LOGW("phornyac: accept_loop: sockfd_settings=%d, sockfd_app=%d",
            sockfd_settings, sockfd_app);
    err_count = 0;
    
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
        LOGE("phornyac: accept_loop: should have %d poll_fds, returning -1",
                POLL_NFDS);
        return -1;
    }

    /**
     * Loop, accepting socket connections as they occur...
     */
    while (1) {
        if (err_count >= MAX_ERRORS) {
            LOGW("phornyac: accept_loop: reached max number of errors (%d), "
                    "returning -1", err_count);
            return -1;
        }

        /* Poll on the fds we're waiting for connections from: */
        ret = poll((struct pollfd *)poll_fds, poll_nfds, poll_timeout);
        if (ret < 0) {
            LOGW("phornyac: accept_loop: error number: %d", errno);
            LOGW("phornyac: accept_loop: poll() returned %d, "
                    "looping again", ret);
            err_count++;
            continue;
        }
        else if (ret == 0) {
            LOGW("phornyac: accept_loop: poll() timed out... re-looping");
            err_count++;
            continue;
        }
        LOGW("phornyac: accept_loop: poll() returned %d fds ready to read",
                ret);

        /**
         * Handle the fds that are ready to be read:
         */
        for (i = 0; i < POLL_NFDS; i++) {
            if (poll_fds[i].revents & (POLLERR | POLLHUP | POLLNVAL)) {
                LOGW("phornyac: accept_loop: poll_fds[%d] has error 0x%X "
                        "(POLLERR=0x%X, POLLHUP=0x%X, POLLNVAL=0x%X), "
                        "continuing",
                        i, poll_fds[i].revents,
                        POLLERR, POLLHUP, POLLNVAL);
                err_count++;
                continue;
            } else if (poll_fds[i].revents & POLLIN) {
                LOGW("phornyac: accept_loop: poll_fds[%d] has event POLLIN",
                        i);
                switch(i) {
                case 0:  /* listening socket: sockfd_settings */
                    ret = accept_settings(sockfd_settings);
                    if (ret < 0) {
                        LOGW("phornyac: accept_loop: accept_settings() "
                                "returned error %d, doing nothing",
                                ret);
                        err_count++;
                    }
                    break;
                case 1:  /* listening socket: sockfd_app */
                    ret = accept_app(sockfd_app);
                    if (ret < 0) {
                        LOGW("phornyac: accept_loop: accept_app() "
                                "returned error %d, doing nothing",
                                ret);
                        err_count++;
                    }
                    break;
                default: /* already-connected socket */
                    LOGW("phornyac: accept_loop: got poll event on "
                            "already-connected socket");
                    err_count++;
                }
            } else {
                /**
                 * poll() didn't get a POLLIN or an error for this fd,
                 * so do nothing.
                 */
                LOGW("phornyac: accept_loop: nothing to do for poll_fds[%d]",
                        i);
            }
        }
        LOGW("phornyac: accept_loop: reached end of while loop, err_count=%d",
                err_count);
    }
}
#endif

int main(int argc, char* argv[]) {
    int i, ret;
    int sockfd_settings, sockfd_app;

    LOGW("phornyac: main: entered, argc=%d\n", argc);
#ifdef DELAY_START
    LOGW("phornyac: main: sleeping for %d secs to wait for logging to start\n",
            SECONDS);
    sleep(SECONDS);
    for (i = 0; i < argc; i++) {
        LOGW("phornyac: main: argv[%d]=%s\n", i, argv[i]);
    }
#endif

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
        LOGW("phornyac: main: initialize_policydb() returned %d, returning -1",
                ret);
        return -1;
    }

    /**
     * Open the socket that the Settings app connects to to perform
     * policy database updates:
     */
    sockfd_settings = android_get_control_socket(POLICYD_UPDATESOCK);
    if (sockfd_settings < 0) {
        LOGW("phornyac: main: error number: %d", errno);
        LOGW("phornyac: main: could not open socket \"%s\", returning -1",
                POLICYD_UPDATESOCK);
        return -1;
    }
    if (listen(sockfd_settings, 1) < 0) {
        LOGW("phornyac: main: error number: %d", errno);
        LOGW("phornyac: main: could not listen on socket \"%s\", returning -1",
                POLICYD_UPDATESOCK);
        return -1;
    }
 
    /**
     * Open the socket that application VMs connect to to request 
     * policy checks:
     */
    sockfd_app = android_get_control_socket(POLICYD_SOCK);
    if (sockfd_app < 0) {
        LOGW("phornyac: main: error number: %d", errno);
        LOGW("phornyac: main: could not open socket \"%s\", returning -1",
                POLICYD_SOCK);
        return -1;
    }
    if (listen(sockfd_app, BACKLOG) < 0) {
        LOGW("phornyac: main: error number: %d", errno);
        LOGW("phornyac: main: could not listen on socket \"%s\", returning -1",
                POLICYD_SOCK);
        return -1;
    }
    
    ret = accept_loop(sockfd_settings, sockfd_app);
    if (ret < 0) {
        LOGW("phornyac: main: accept_loop returned error %d, returning -1",
                ret);
        return -1;
    }
    LOGW("phornyac: main: accept_loop returned success (%d)",
            ret);
   
    LOGW("phornyac: main: reached end of main, returning 0");
    return 0;
}

