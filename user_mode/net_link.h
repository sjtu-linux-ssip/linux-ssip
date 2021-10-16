#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>
#include <linux/netlink.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>

#define NETLINK_TEST    30
#define MSG_LEN            125
#define MAX_PLOAD        125

typedef struct _user_msg_info
{
    struct nlmsghdr hdr;
    char  msg[MSG_LEN];
} user_msg_info;

typedef struct nl_socket
{
    int skfd;
    int ret;
    user_msg_info u_info;
    socklen_t len;
    struct nlmsghdr *nlh;
    struct sockaddr_nl saddr, daddr;
    char *umsg;
    int port_id;
} nl_socket;

/*
使用示例：
    char* msg="hello world!";   
    nl_socket nl_kill;
    printf("a");
    nl_init(100,&nl_kill);
    nl_recv(&nl_kill);
    nl_send(msg,&nl_kill);
    nl_close(&nl_kill);

*/
void nl_init(int port, nl_socket *nl);
void nl_recv(nl_socket *nl);
void nl_send(char *msg,nl_socket *nl);
void nl_close(nl_socket *nl)
