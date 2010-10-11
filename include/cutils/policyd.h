/* Added by Peter Hornyack, 2010-10-09 */

#define POLICYD_MSG_SIZE 128

typedef struct policyd_message {
    char msg[POLICYD_MSG_SIZE];
} policyd_msg;

int initialize_policydb();
int handle_connection(int);
