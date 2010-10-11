/* Added by Peter Hornyack, 2010-10-09 */

#include "sockets.h"

#define POLICYD_MSG_SIZE    128
#define POLICYD_SOCK        "policyd"
#define POLICYD_UPDATESOCK  "policyd_update"
#define POLICYD_NSPACE      ANDROID_SOCKET_NAMESPACE_RESERVED
#define POLICYD_SOCKTYPE    SOCK_STREAM  //alternative: SOCK_DGRAM

typedef struct policyd_message {
    char msg[POLICYD_MSG_SIZE];
} policyd_msg;

int initialize_policydb();
int handle_connect_settings(int);
int handle_connect_app(int);
int handle_connection(int);

