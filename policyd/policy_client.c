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
#include "policy_global.h"

#ifdef LOG_TAG
#undef LOG_TAG
#define LOG_TAG "policy_client"
#endif

/**
 * Fills in the designated policy_req struct with the given fields.
 * Returns: size of policy_req on success, negative on error.
 */
int construct_policy_req(policy_req *msg, int request_code,
        const char *process_name, const char *dest_name,
        int taint_tag) {
    //LOGW("phornyac: construct_policy_req: entered");
    if (msg == NULL) {
        LOGW("phornyac: construct_policy_req: msg is NULL, "
                "returning -1");
        return -1;
    }

    msg->request_code = request_code;
    msg->entry.taint_tag = taint_tag;
    msg->entry.app_status = -1;  /* currently unused */
    
    if (process_name == NULL) {
        LOGW("phornyac: construct_policy_req: warning, process_name "
                "is NULL!");
        msg->entry.process_name[0] = '\0';
    } else {
        if (strlen(process_name) >= POLICYD_STRING_SIZE) {
            LOGW("phornyac: construct_policy_req: process_name too long, "
                    "returning -1");
            return -1;
        }
        strncpy(msg->entry.process_name, process_name,
                POLICYD_STRING_SIZE-1);
        msg->entry.process_name[POLICYD_STRING_SIZE-1] = '\0';
    }

    if (dest_name == NULL) {
        LOGW("phornyac: construct_policy_req: warning, dest_name "
                "is NULL!");
        msg->entry.dest_name[0] = '\0';
    } else {
        if (strlen(dest_name) >= POLICYD_STRING_SIZE) {
            LOGW("phornyac: construct_policy_req: dest_name too long, "
                    "returning -1");
            return -1;
        }
        strncpy(msg->entry.dest_name, dest_name,
                POLICYD_STRING_SIZE-1);
        msg->entry.dest_name[POLICYD_STRING_SIZE-1] = '\0';
    }

    //LOGW("phornyac: construct_policy_req: returning sizeof(policy_req) "
    //        "(%d)", sizeof(policy_req));
    return (sizeof(policy_req));
}

int send_policy_request(int sockfd, policy_req *request,
        policy_resp *response) {
    int ret;
    //LOGW("phornyac: send_policy_request: entered");

    //LOGW("phornyac: send_policy_request: calling send_policy_req() "
    //        "with sockfd=%d", sockfd);
    ret = send_policy_req(sockfd, request);
    if (ret < 0) {
        LOGW("phornyac: send_policy_request: send_policy_req() "
                "returned error=%d", ret);
        LOGW("phornyac: send_policy_request: returning -1");
        return -1;
    }

    //LOGW("phornyac: send_policy_request: send_policy_req() succeeded, "
    //        "calling recv_policy_resp()");
    ret = recv_policy_resp(sockfd, response);
    if (ret < 0) {
        LOGW("phornyac: send_policy_request: recv_policy_resp() "
                "returned error=%d", ret);
        LOGW("phornyac: send_policy_request: returning -1");
        return -1;
    }
    //TODO XXX: recv_policy_resp() is returning 0 on certain errors (server
    //  closes socket), so we're saying success here!!!
    LOGW("phornyac: send_policy_request: recv_policy_resp() succeeded, "
            "printing response");
    print_policy_resp(response);

    //LOGW("phornyac: send_policy_request: returning 0");
    return 0;
}
