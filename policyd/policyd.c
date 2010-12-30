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
#include <sys/inotify.h>
#include <errno.h>
#include <utils/Log.h>
#include <cutils/sockets.h>
#include <policy_global.h>
#include <policydb.h>

#ifdef LOG_TAG
#undef LOG_TAG
#define LOG_TAG "policyd"
#endif

#define BACKLOG 12           /* No idea if this is appropriate... */
#define MAX_ERRORS 100       /* Maximum number of errors before we exit */
#define SECONDS 20
#define RESPONSE_TIMEOUT 5   /* Seconds that we wait for app to read() our reply */

/**
 * Extremely important global variables:
 *   global_enable_enforcement: 0 means that enforcement has been disabled
 *     and all queries will return "allow"; anything else means that
 *     enforcement will be performed as usual.
 *   global_default_allow: 1 means that we default to "allowing" a
 *     transmission if there are no matching entries in the policy db;
 *     0 means that we block all transmissions UNLESS there is at least
 *     one matching entry in the db.
 */
int global_enable_enforcement = 1;
int global_default_allow = 1;

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
 * Initializes the policy database by calling the policydb component's
 * init function.
 * Returns: 0 on success, negative on error.
 */
int init_db() {
    LOGW("phornyac: init_db(): entered");
    int ret;

    LOGW("phornyac: init_db(): calling initialize_policydb()");
    ret = initialize_policydb();
    if (ret < 0) {
        LOGW("phornyac: init_db(): initialize_policydb() returned "
                "error=%d, returning -1", ret);
        return -1;
    }

    LOGW("phornyac: init_db(): returning 0");
    return 0;
}

/**
 * Adds a watch to an inotify instance for our policy XML file. The
 * fd passed into this function represents an existing inotify
 * instance; if the argument is negative, then this function will
 * create a new inotify instance first.
 * Returns: the file descriptor for the inotify instance, or
 *   -1 on error.
 */
int inotify_setup(int inotify_fd) {
    int fd, ret;
    uint32_t mask;
    LOGW("phornyac: inotify_setup: entered, arg inotify_fd=%d",
            inotify_fd);

    if (inotify_fd > 0) {
        fd = inotify_fd;
    } else {
        fd = inotify_init();
        if (fd < 0) {
            LOGW("phornyac: inotify_setup: inotify_init() returned "
                    "error=%d, returning -1", errno);
            return -1;
        }
    }

    /* When adb push is used to overwrite the policy XML file, inotify
     * reports it as a IN_DELETE_SELF event. We just watch for all
     * events on this file to make sure that we don't miss anything.
     * inotify_add_watch() returns a "watch descriptor" that uniquely
     * identifies this particular watch when read() is called on the
     * inotify event queue fd. Since we're only interested in watching
     * one file for now, we don't do anything with the watch descriptor.
     */
    LOGW("phornyac: inotify_setup: adding watch for "
            "policydb_xmlfile=%s", policydb_xmlfile);
    mask = IN_ALL_EVENTS;
    ret = inotify_add_watch(fd, policydb_xmlfile, mask);
    if (ret < 0) {
        LOGW("phornyac: inotify_setup: inotify_add_watch() returned "
                "error=%d, returning -1", errno);
        return -1;
    }
    LOGW("phornyac: inotify_setup: inotify_add_watch() returned "
            "watch descriptor %d", ret);

    LOGW("phornyac: inotify_setup: setup successful, returning "
            "inotify fd=%d", fd);
    return fd;
}

/**
 * Handles an inotify event on the given fd. When this function returns
 * an error, the inotify_fd passed to it should be closed and re-opened
 * (see comments below for more details).
 * Returns: 0 on success, -1 on error.
 */
int handle_inotify_event(int inotify_fd) {
    int ret, bufsize;
    struct inotify_event event;
    LOGW("phornyac: handle_inotify_event: entered");

    /* Read the inotify event: */
    bufsize = sizeof(struct inotify_event);
    ret = read(inotify_fd, &event, bufsize);
    if (ret != bufsize) {
        if (ret < 0) {
            LOGW("phornyac: handle_inotify_event: read() returned "
                    "error=%d, returning -1", errno);
            return -1;
        } else {
            LOGW("phornyac: handle_inotify_event: read() expected "
                    "%d bytes, but only got %d; should read() again, "
                    "but being lazy and just returning -1",
                    bufsize, ret);
            return -1;
        }
    }

    /* When a new policy file is pushed onto the device using adb push,
     * it doesn't count as an IN_MODIFY event; instead, it appears that
     * the file is deleted and then written again. Therefore, inotify
     * generates an IN_DELETE_SELF event; I've also seen IN_IGNORED and
     * IN_ATTRIB events here. Therefore, after we receive ANY inotify event
     * here, we always refresh the database, and then we tell the
     * caller that the inotify_fd is not invalid (since the inode was
     * replaced) unless we really did see an IN_MODIFY event.
     */
    LOGW("phornyac: handle_inotify_event: successfully read inotify_event: "
            "wd=%d, mask=0x%X", event.wd, event.mask);
    LOGW("phornyac: handle_inotify_event: calling refresh_policydb()");
    ret = refresh_policydb();
    if (ret < 0) {
        LOGW("phornyac: handle_inotify_event: refresh_policydb() "
                "returned error=%d, returning -1", ret);
        return -1;
    }

    if (!(event.mask & IN_MODIFY)) {
        LOGW("phornyac: handle_inotify_event: event mask does not contain "
                "IN_MODIFY, returning -1");
        return -1;
    }
    LOGW("phornyac: handle_inotify_event: event mask contained IN_MODIFY, "
            "returning 0");
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
 * Queries the policy db with the given entry and determines
 * the appropriate response.
 * Returns: a response code, or negative on error.
 */
int handle_query(policy_entry *entry) {
    int ret;

    if (global_enable_enforcement == 0) {
        LOGW("phornyac: handle_query: policy enforcement is disabled, "
                "returning POLICY_RESP_ALLOW");
        return POLICY_RESP_ALLOW;
    }
    LOGW("phornyac: handle_query: global_enable_enforcement is set, "
            "continuing with enforcement");

    LOGW("phornyac: handle_query: calling query_policydb()");
    ret = query_policydb(entry);
    if (ret < 0) {
        LOGW("phornyac: handle_query: query_policydb() returned "
                "error=%d, returning -1", ret);
        return -1;
    } else if (ret == 0) {
        LOGW("phornyac: handle_query: query_policydb() returned 0, "
                "no entries match");
        if (global_default_allow) {
            LOGW("phornyac: handle_query: default is to allow, so "
                    "returning POLICY_RESP_ALLOW");
            return POLICY_RESP_ALLOW;
        } else {
            LOGW("phornyac: handle_query: default is to deny, so "
                    "returning POLICY_RESP_BLOCK");
            return POLICY_RESP_BLOCK;
        }
    } else {
        LOGW("phornyac: handle_query: query_policydb() returned %d "
                "matching entries", ret);
        if (global_default_allow) {
            LOGW("phornyac: handle_query: default is to allow, so "
                    "returning POLICY_RESP_BLOCK");
            return POLICY_RESP_BLOCK;
        } else {
            LOGW("phornyac: handle_query: default is to deny, so "
                    "returning POLICY_RESP_ALLOW");
            return POLICY_RESP_ALLOW;
        }
    }

    return -1;
}

/**
 * Returns: a response code, or negative on error.
 */
int handle_add_entry(policy_entry *entry) {
    int ret;

    LOGW("phornyac: handle_add_entry: calling add_policydb_entry()");
    ret = add_policydb_entry(entry);
    if (ret != 1) {
        LOGW("phornyac: handle_add_entry: add_policydb_entry() did "
                "not return 1, so we're returning -1");
        return -1;
    }

    LOGW("phornyac: handle_add_entry: add_policydb_entry() returned "
            "%d entry added, returning POLICY_RESP_SUCCESS", ret);
    return POLICY_RESP_SUCCESS;
}

/**
 * Returns: a response code, or negative on error.
 */
int handle_del_entry(policy_entry *entry) {
    int ret;

    LOGW("phornyac: handle_del_entry: calling remove_policydb_entries()");
    ret = remove_policydb_entries(entry);
    if (ret < 0) {
        LOGW("phornyac: handle_del_entry: remove_policydb_entries() "
                "returned error, so we're returning -1");
        return -1;
    }

    LOGW("phornyac: handle_add_entry: remove_policydb_entries() returned "
            "%d entries removed, returning POLICY_RESP_SUCCESS", ret);
    return POLICY_RESP_SUCCESS;
    return -1;
}

/**
 * Examines the request code for the incoming request, takes the
 * appropriate action, and returns a response code to be sent back
 * to the client. Certain actions can only be performed if the
 * request is from the Settings app.
 * Returns: a response code, or negative on error.
 */
int switch_on_request(policy_req *request, int from_settings) {
    int ret;
    LOGW("phornyac: switch_on_request: entered");
    
#if 0
    POLICY_REQ_QUERY,         //Query the db for this transmission
    POLICY_UPDATE_ENABLE,     //Globally enable policy enforcement
    POLICY_UPDATE_DISABLE,    //Globally disable policy enforcement
    POLICY_UPDATE_DEF_ALLOW,  //Change enforcement to default-allow
    POLICY_UPDATE_DEF_DENY,   //Change enforcement to default-deny
    POLICY_UPDATE_ADD,        //Add entry to policy db
    POLICY_UPDATE_DEL,        //Remove all matching entries from policy db
    POLICY_RESP_ALLOW,        //Allow this transmission to proceed
    POLICY_RESP_BLOCK,        //Block this transmission
    POLICY_RESP_SUCCESS,      //Db update succeeded
#endif

    switch (request->request_code) {
    case POLICY_REQ_QUERY:
        LOGW("phornyac: switch_on_request: case POLICY_REQ_QUERY");
        if (from_settings) {
            LOGW("phornyac: switch_on_request: from_settings is true "
                    "for case POLICY_REQ_QUERY, is this really what we "
                    "want??");
        }
        return handle_query(&(request->entry));
    case POLICY_UPDATE_ENABLE:
        LOGW("phornyac: switch_on_request: case POLICY_UPDATE_ENABLE");
        if (!from_settings)
            goto no_permission;
        global_enable_enforcement = 1;
        LOGW("phornyac: switch_on_request: set global_enable_enforcement=%d",
                global_enable_enforcement);
        return POLICY_RESP_SUCCESS;
    case POLICY_UPDATE_DISABLE:
        LOGW("phornyac: switch_on_request: case POLICY_UPDATE_DISABLE");
        if (!from_settings)
            goto no_permission;
        global_enable_enforcement = 0;
        LOGW("phornyac: switch_on_request: set global_enable_enforcement=%d",
                global_enable_enforcement);
        return POLICY_RESP_SUCCESS;
    case POLICY_UPDATE_DEF_ALLOW:
        LOGW("phornyac: switch_on_request: case POLICY_UPDATE_DEF_ALLOW");
        if (!from_settings)
            goto no_permission;
        global_default_allow = 1;
        LOGW("phornyac: switch_on_request: set global_default_allow=%d",
                global_default_allow);
        return POLICY_RESP_SUCCESS;
    case POLICY_UPDATE_DEF_DENY:
        LOGW("phornyac: switch_on_request: case POLICY_UPDATE_DEF_DENY");
        if (!from_settings)
            goto no_permission;
        global_default_allow = 0;
        LOGW("phornyac: switch_on_request: set global_default_allow=%d",
                global_default_allow);
        return POLICY_RESP_SUCCESS;
    case POLICY_UPDATE_ADD:
        LOGW("phornyac: switch_on_request: case POLICY_UPDATE_ADD");
        if (!from_settings)
            goto no_permission;
        return handle_add_entry(&(request->entry));
     case POLICY_UPDATE_DEL:
        LOGW("phornyac: switch_on_request: case POLICY_UPDATE_DEL");
        if (!from_settings)
            goto no_permission;
        return handle_del_entry(&(request->entry));
    default:
        LOGW("phornyac: switch_on_request: default case, returning error");
        return -1;
    }

    LOGW("phornyac: switch_on_request: reached end, returning -1");
    return -1;
no_permission:
    LOGW("phornyac: switch_on_request: received update from an app "
            "that's not the Settings app, returning -1");
    return -1;
}

/**
 * Handles a connection from an application VM or from the Settings
 * app on the given socket fd. First receives the message from the
 * socket, then formulates a response and sends it back. This
 * function assumes that after the sender sends its request here,
 * it will immediately try to receive our response, so we do not
 * do a select() to wait for the other side to be ready for reading.
 * Update requests will fail if from_settings is not set.
 * Returns: 0 on success, negative on error. On error, the socket
 *   should be closed.
 */
int handle_request(int sockfd, int from_settings) {
    int ret, size;
    policy_req request;
    policy_resp response;
    int response_code;
    LOGW("phornyac: handle_request: entered");

    /* First, get the request: */
    ret = recv_policy_req(sockfd, &request);
    if (ret < 0) {
        LOGW("phornyac: handle_request: recv_policy_req() returned "
                "error %d, returning -1", ret);
        return -1;
    } else if (ret == 1) {
        LOGW("phornyac: handle_request: recv_policy_req() returned "
                "1, indicating that other side closed its socket; "
                "returning -1");
        return -1;
    }
    LOGW("phornyac: handle_request: recv_policy_req() succeeded, printing "
            "request:");
    print_policy_req(&request);

    /* Formulate the response: */
    LOGW("phornyac: handle_request: passing request to switch_on_request()");
    ret = switch_on_request(&request, from_settings);
    if (ret < 0) {
        LOGW("phornyac: handle_request: switch_on_request() returned "
                "error=%d, returning -1", ret);
        return -1;
    }
    response_code = ret;
    LOGW("phornyac: handle_request: switch_on_request() returned "
            "response code %d", response_code);

    ret = construct_policy_resp(&response, response_code);
    if (ret < 0) {
        LOGW("phornyac: handle_request: construct_policy_resp() "
                "returned error %d, so we're returning -1", ret);
        return -1;
    }

    /* Finally, send the response: */
    ret = send_policy_resp(sockfd, &response);
    if (ret < 0) {
        LOGW("phornyac: handle_request: send_policy_resp() returned "
                "error %d, returning -1", ret);
        return -1;
    }
    LOGW("phornyac: handle_request: send_policy_resp() succeeded, "
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
int accept_loop(int inotify_fd, int sockfd_settings, int sockfd_app) {
    int i, ret, err_count;
    int nfds;
    int accepted_settings_fd = -1;
    int from_settings = 0;
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
    FD_SET(inotify_fd, &rd_set);
    FD_SET(sockfd_settings, &rd_set);
    FD_SET(sockfd_app, &rd_set);
    nfds = max(inotify_fd, sockfd_settings);
    nfds = max(nfds, sockfd_app);
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
                if (i == inotify_fd) {  /* policydb XML file has changed */
                    LOGW("phornyac: accept_loop: inotify_fd ready for "
                            "reading, policydb XML file has changed");
                    LOGW("phornyac: accept_loop: calling "
                            "handle_inotify_event()");
                    ret = handle_inotify_event(i);
                    if (ret < 0) {
                        LOGW("phornyac: accept_loop: handle_inotify_event() "
                                "returned error %d, so closing inotify_fd "
                                "and calling inotify_setup(-1) again", ret);
                        close(inotify_fd);
                        inotify_fd = inotify_setup(-1);
                        nfds = max(nfds, inotify_fd);
                        if (ret < 0) {
                            LOGW("phornyac: accept_loop: "
                                    "inotify_setup() returned error=%d, "
                                    "ignoring", ret);
                        }
                    }
                } else if (i == sockfd_settings) {  /* New connection from Settings */
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
                } else {
                    /* Check if the request is from the settings app: */
                    if (i == accepted_settings_fd) {
                        LOGW("phornyac: accept_loop: existing connection from "
                                "Settings");
                        from_settings = 1;
                    } else {
                        LOGW("phornyac: accept_loop: existing connection from "
                                "app");
                        from_settings = 0;
                    }
                    /* Handle the request: */
                    ret = handle_request(i, from_settings);
                    if (ret < 0) {
                        LOGW("phornyac: accept_loop: handle_request() "
                                "returned error %d, closing its fd %d",
                                ret, i);
                        close(i);
                        if (from_settings)
                            accepted_settings_fd = -1;
                        FD_CLR(i, &rd_set);
                        err_count++;
                    }
                    LOGW("phornyac: accept_loop: handle_request() "
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

//#undef DELAY_START
#define DELAY_START

int main(int argc, char* argv[]) {
    int i, ret;
    int inotify_fd;
    int sockfd_settings, sockfd_app;

    LOGW("phornyac: main: entered, argc=%d\n", argc);
#ifdef DELAY_START
    LOGW("phornyac: main: sleeping for %d secs to delay start\n",
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
    ret = init_db();
    if (ret) {
        LOGW("phornyac: main: init_db() returned %d, returning -1",
                ret);
        return -1;
    }

    /* Setup inotify so that we can refresh the db whenever the policy
     * file is changed: */
    inotify_fd = inotify_setup(-1);
    if (inotify_fd < 0) {
        LOGW("phornyac: main: inotify_setup() returned %d, returning -1",
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
    
    ret = accept_loop(inotify_fd, sockfd_settings, sockfd_app);
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

