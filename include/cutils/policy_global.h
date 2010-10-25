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

/**
 * Contains definitions that need to be seen by both the client
 * and the server side of the policy database.
 */

#ifndef POLICY_GLOBAL_H
#define POLICY_GLOBAL_H

#define POLICYD_SOCK         "policyd"
#define POLICYD_UPDATESOCK   "policyd_update"
#define POLICYD_NSPACE       ANDROID_SOCKET_NAMESPACE_RESERVED
#define POLICYD_SOCKTYPE     SOCK_STREAM  /* alternative: SOCK_DGRAM */
#define POLICYD_STRING_SIZE  128

/**
 * Policy request and response codes. UPDATE codes are only for use
 * by the "Settings" app that has permission to access policyd's
 * update socket (see system/core/rootdir/init.rc).
 */
enum {
    POLICY_BASE = 0,
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
};

/**
 * This struct should correspond exactly to the rows that are
 * stored in the policydb sqlite database:
 */
typedef struct _policy_entry {
    char process_name[POLICYD_STRING_SIZE];
    char dest_name[POLICYD_STRING_SIZE];
    int taint_tag;
    int app_status;  /* currently unused */
} policy_entry;

typedef struct _policy_req {
    int request_code;
    policy_entry entry;
} policy_req;

typedef struct _policy_resp {
    int response_code;
} policy_resp;

#if 0
/**
 * For use by Settings app;
 */
typedef struct policy_update_request {
    int request_code;
    policy_entry entry;
} policy_update_req;

/* For use by Settings app: */
typedef struct policy_update_response {
    int response_code;
} policy_update_resp;
#endif

/**
 * Sends a policy_req struct to the given socket. The send will
 * block until the socket is ready to be written to, so the calling
 * function should perform a poll/select to ensure this.
 * Returns: 0 on success, -1 on error. On an error, the caller should
 *   probably close the socket.
 */
int send_policy_req(int sockfd, policy_req *msg);

/**
 * Receives a policy_req struct from the given socket. The receive
 * will block until an entire message is available to read, so the
 * calling function should perform a poll/select first to make sure
 * that data is available for reading.
 * Returns: 0 on success, 1 if server closed socket, -1 if error.
 *   On success, the policy_req is filled, of course. On
 *   an error, the caller should probably close the socket.
 */
int recv_policy_req(int sockfd, policy_req *msg);

/**
 * Sends a policy_resp struct to the given socket. When called after a
 * recv_policy_req() on the same socket, this function will successfully
 * send (without blocking), even if the receiver has not yet been
 * scheduled in to call recv_policy_resp() yet.
 * Returns: 0 on success, -1 on error. On an error, the caller should
 *   probably close the socket.
 */
int send_policy_resp(int sockfd, policy_resp *msg);

/**
 * Receives a policy_resp struct from the given socket. The receive
 * will block until an entire message is available to read, so the
 * calling function should perform a poll/select first to make sure
 * that data is available for reading.
 * Returns: 0 on success, 1 if server closed socket, -1 if error.
 *   On success, the policy_resp is filled, of course. On
 *   an error, the caller should probably close the socket.
 */
int recv_policy_resp(int sockfd, policy_resp *msg);

/**
 * Debugging function that prints out the contents of a policy_req
 * struct.
 */
void print_policy_req(policy_req *msg);

/**
 * Debugging function that prints out the contents of a policy_resp
 * struct.
 */
void print_policy_resp(policy_resp *msg);

#endif
