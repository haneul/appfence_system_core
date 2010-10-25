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
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <errno.h>
#include <utils/Log.h>
#include <cutils/sockets.h>
#include <policy_global.h>
#include <policydb.h>

#ifdef LOG_TAG
#undef LOG_TAG
#define LOG_TAG "policyd"
#endif

//#define POLL_NFDS 2        /* Number of fds we need to poll/select on */
//#define POLL_TIMEOUT -1    /* Negative means infinite timeout */
#define BACKLOG 12           /* No idea if this is appropriate... */
#define MAX_ERRORS 100       /* Maximum number of errors before we exit */
#define SECONDS 20
#define RESPONSE_TIMEOUT 5   /* Seconds that we wait for app to read() our reply */
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
 * Fills in the designated policy_resp struct with the given fields.
 * Returns: size of policy_resp on success, negative on error.
 */
int construct_policy_resp(policy_resp *msg, int response_code) {
    LOGW("phornyac: construct_policy_resp: entered");

    msg->response_code = response_code;

    LOGW("phornyac: construct_policy_resp: returning sizeof(policy_resp) "
            "(%d)", sizeof(policy_resp));
    return (sizeof(policy_resp));
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
    policy_req msg_send;

    LOGW("phornyac: handle_request_settings: entered");

    //XXX: this gets called when the socket is ready for READING;
    //  need to update it to read() first, then write()!

    LOGW("phornyac: handle_request_settings: NEEDS RE-IMPLEMENTING, "
        "RETURNING 0");
    return 0;
}

/**
 * Handles a connection from an application VM on the
 * given socket fd. First receives the message from the socket,
 * then formulates a response and sends it back. This function
 * assumes that after the sender sends its request here, it will
 * immediately try to receive our response, so we do not do a
 * select() to wait for the other side to be ready for reading.
 * Returns: 0 on success, negative on error. On error, the socket
 *   should be closed.
 */
int handle_request_app(int sockfd) {
    int ret, size;
    policy_req request;
    policy_resp response;
    int response_code;
    LOGW("phornyac: handle_request_app: entered");

    /* First, get the request: */
    ret = recv_policy_req(sockfd, &request);
    if (ret < 0) {
        LOGW("phornyac: handle_request_app: recv_policy_req() returned "
                "error %d, returning -1", ret);
        return -1;
    } else if (ret == 1) {
        LOGW("phornyac: handle_request_app: recv_policy_req() returned "
                "1, indicating that other side closed its socket; "
                "returning -1");
        return -1;
    }
    LOGW("phornyac: handle_request_app: recv_policy_req() succeeded, printing "
            "request:");
    print_policy_req(&request);

    /* Formulate the response: */
    //XXX: actually do something here!
    LOGW("phornyac: handle_request_app: TODO: access policy database to "
            "handle request; for now, setting response code to 1");
    response_code = 1;
    ret = construct_policy_resp(&response, response_code);
    if (ret < 0) {
        LOGW("phornyac: handle_request_app: construct_policy_resp() "
                "returned error %d, so we're returning -1", ret);
        return -1;
    }

    /* Finally, send the response: */
    ret = send_policy_resp(sockfd, &response);
    if (ret < 0) {
        LOGW("phornyac: handle_request_app: send_policy_resp() returned "
                "error %d, returning -1", ret);
        return -1;
    }
    LOGW("phornyac: handle_request_app: send_policy_resp() succeeded, "
            "returning 0");
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
        LOGW("phornyac: accept_loop: sockfd_settings=%d, "
                "sockfd_app=%d, accepted_settings_fd=%d",
                sockfd_settings, sockfd_app, accepted_settings_fd);
        LOGW("phornyac: accept_loop: calling select() with nfds=%d and "
                "NULL timeout", nfds);
        ret = select(nfds + 1, &rd_ret, &wr_ret, &er_ret, NULL);
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
                    if (ret < 0) {
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
                    if (ret < 0) {
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
            } else if (FD_ISSET(i, &wr_ret)) {
                LOGW("phornyac: accept_loop: fd %d is ready for writing? "
                        "...doing nothing", i);
            } else if (FD_ISSET(i, &er_ret)) {
                LOGW("phornyac: accept_loop: fd %d has exception? "
                        "...doing nothing", i);
            } else {
                LOGW("phornyac: accept_loop: nothing to do for fd %d", i);
            }
            //TODO: when do we close fds???
        } //for()

        //XXX: when do we exit the while loop??
        LOGW("phornyac: accept_loop: reached end of while loop, "
                "looping again");

    } //while()
    LOGW("phornyac: accept_loop: finished (why?), returning 0");
    return 0;
}

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

