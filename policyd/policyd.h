/* Added by Peter Hornyack, 2010-10-09 */

#ifdef LOG_TAG
#undef LOG_TAG
#define LOG_TAG "policyd"
#endif

#define POLICYD_MSG_SIZE 128

struct policyd_msg {
    char msg[POLICYD_MSG_SIZE];
};

int initialize_policydb();
int handle_connection(int);
