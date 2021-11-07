/*
 *  `nl_wrapper.h`: wrapper for netlink basic methods
 */

#ifndef USER_MODE_NL_WRAPPER_H
#define USER_MODE_NL_WRAPPER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#define MSG_LEN 256
#define MAX_PLOAD 256

typedef struct {
    struct nlmsghdr hdr;
    char  msg[MSG_LEN];
} user_msg_info;

typedef struct {
    int skfd;
    int ret;
    user_msg_info u_info;
    socklen_t len;
    struct nlmsghdr *nlh;
    struct sockaddr_nl saddr, daddr;
    char *umsg;
    int port_id;
} nl_socket;

void nl_init(int port, nl_socket *nl);
void nl_recv(nl_socket *nl);
void nl_send(char *msg, nl_socket *nl);
void nl_close(nl_socket *nl);

#endif //USER_MODE_NL_WRAPPER_H
