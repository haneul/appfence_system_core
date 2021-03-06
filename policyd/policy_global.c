/*
 * Copyright (C) 2007 The Android Open Source Project
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
#include <sys/types.h>
#include <sys/socket.h>
#include "policy_global.h"

#ifdef LOG_TAG
#undef LOG_TAG
#define LOG_TAG "policy_global"
#endif

int send_policy_req(int sockfd, policy_req *msg) {
    int size, flags, ret;

    //LOGW("phornyac: send_policy_req: entered");

    size = sizeof(*msg);
    flags = 0;  /* See send(2) */
    //LOGW("phornyac: send_policy_req: calling send() of size %d to fd %d "
    //        "with flags=0x%X", size, sockfd, flags);
    ret = send(sockfd, msg, size, flags);
    if (ret < 0) {
        LOGW("phornyac: send_policy_req: error number: %d (EPIPE=%d)",
                errno, EPIPE);
        LOGW("phornyac: send_policy_req: send() returned error, "
                "returning -1");
        return -1;
    }
    if (ret != size) {
        LOGW("phornyac: send_policy_req: error number: %d", errno);
        LOGW("phornyac: send_policy_req: send() did not complete, "
                "only wrote %d of %d bytes", ret, size);
        LOGW("phornyac: send_policy_req: returning -1");
        return -1;
    }
    //LOGW("phornyac: send_policy_req: send() returned success, "
    //        "returning 0");
    return 0;
}

int recv_policy_req(int sockfd, policy_req *msg) {
    int size, flags, ret;

    //LOGW("phornyac: recv_policy_req: entered");

    size = sizeof(*msg);
    flags = MSG_WAITALL;  /* Block until the FULL message received */
    //LOGW("phornyac: recv_policy_req: calling recv() of size %d from fd %d "
    //        "with flags=0x%X", size, sockfd, flags);
    ret = recv(sockfd, msg, size, flags);
    if (ret < 0) {
        LOGW("phornyac: recv_policy_req: error number: %d", errno);
        LOGW("phornyac: recv_policy_req: recv() returned error, "
                "returning -1");
        return -1;
    }
    if (ret == 0) {
        LOGW("phornyac: recv_policy_req: recv() returned 0, meaning "
                "server has performed orderly shutdown on socket");
        LOGW("phornyac: recv_policy_req: returning 1");
        return 1;
    }
    if (ret != size) {
        LOGW("phornyac: recv_policy_req: error number: %d", errno);
        LOGW("phornyac: recv_policy_req: recv() did not complete, "
                "only got %d of %d bytes", ret, size);
        LOGW("phornyac: recv_policy_req: returning -1");
        return -1;
    }
    //LOGW("phornyac: recv_policy_req: recv() returned success, "
    //        "returning 0");
    return 0;
}

int send_policy_resp(int sockfd, policy_resp *msg) {
    int size, flags, ret;

    //LOGW("phornyac: send_policy_resp: entered");

    size = sizeof(*msg);
    flags = 0;  /* See send(2) */
    //LOGW("phornyac: send_policy_resp: calling send() of size %d to fd %d "
    //        "with flags=0x%X", size, sockfd, flags);
    ret = send(sockfd, msg, size, flags);
    if (ret < 0) {
        LOGW("phornyac: send_policy_resp: error number: %d (EPIPE=%d)",
                errno, EPIPE);
        LOGW("phornyac: send_policy_resp: send() returned error, "
                "returning -1");
        return -1;
    }
    if (ret != size) {
        LOGW("phornyac: send_policy_resp: error number: %d", errno);
        LOGW("phornyac: send_policy_resp: send() did not complete, "
                "only wrote %d of %d bytes", ret, size);
        LOGW("phornyac: send_policy_resp: returning -1");
        return -1;
    }
    //LOGW("phornyac: send_policy_resp: send() returned success, "
    //        "returning 0");
    return 0;
}

int recv_policy_resp(int sockfd, policy_resp *msg) {
    int size, flags, ret;

    //LOGW("phornyac: recv_policy_resp: entered");

    size = sizeof(*msg);
    flags = MSG_WAITALL;  /* Block until the FULL message received */
    //LOGW("phornyac: recv_policy_resp: calling recv() of size %d from fd %d "
    //        "with flags=0x%X", size, sockfd, flags);
    ret = recv(sockfd, msg, size, flags);
    if (ret < 0) {
        LOGW("phornyac: recv_policy_resp: error number: %d", errno);
        LOGW("phornyac: recv_policy_resp: recv() returned error, "
                "returning -1");
        return -1;
    }
    if (ret == 0) {
        LOGW("phornyac: recv_policy_resp: recv() returned 0, meaning "
                "server has performed orderly shutdown on socket");
        LOGW("phornyac: recv_policy_resp: returning 1");
        return 1;
    }
    if (ret != size) {
        LOGW("phornyac: recv_policy_resp: error number: %d", errno);
        LOGW("phornyac: recv_policy_resp: recv() did not complete, "
                "only got %d of %d bytes", ret, size);
        LOGW("phornyac: recv_policy_resp: returning -1");
        return -1;
    }
    //LOGW("phornyac: recv_policy_resp: recv() returned success, "
    //        "returning 0");
    return 0;
}

void print_policy_req(policy_req *msg) {
    /* Use slightly different log format for untainted request,
     * so can be easily separated in logs: */
    if (msg->entry.taint_tag == 0) {
        LOGW("phornyac: print_policy_req: request_code=%d, entry.process_name=%s, "
                "entry.dest_name=%s, entry.hostname=%s, entry untainted, "
                "entry.app_status=%d",
                msg->request_code, msg->entry.process_name, msg->entry.dest_name,
                msg->entry.hostname, msg->entry.app_status);
    } else {
        LOGW("phornyac: print_policy_req: request_code=%d, entry.process_name=%s, "
                "entry.dest_name=%s, entry.hostname=%s, entry.taint_tag=0x%X, "
                "entry.app_status=%d",
                msg->request_code, msg->entry.process_name, msg->entry.dest_name,
                msg->entry.hostname, msg->entry.taint_tag, msg->entry.app_status);
    }
}

void print_policy_resp(policy_resp *msg) {
    LOGW("phornyac: print_policy_resp: response_code=%d",
            msg->response_code);
}

