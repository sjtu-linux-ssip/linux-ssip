/*
 *  `nl_wrapper.c`: wrapper for netlink basic methods
 */

#include <utils/nl_wrapper.h>

void nl_init(int port, nl_socket *nl, int nl_family) {
    nl->nlh = NULL;
    nl->port_id = port;
    nl->skfd = socket(AF_NETLINK, SOCK_RAW, nl_family);
    if (nl->skfd == -1) {
        // perror("create socket error\n");
        return;
    }
    // printf("create OK\n");

    memset(&(nl->saddr), 0, sizeof(nl->saddr));
    nl->saddr.nl_family = AF_NETLINK;
    nl->saddr.nl_pid = port;
    nl->saddr.nl_groups = 0;
    if (bind(nl->skfd, (struct sockaddr *)&(nl->saddr), sizeof(nl->saddr)) != 0) {
        perror("bind() error\n");
        close(nl->skfd);
        return;
    }

    // printf("bind OK\n");

    memset(&(nl->daddr), 0, sizeof(nl->daddr));
    (nl->daddr).nl_family = AF_NETLINK;
    (nl->daddr).nl_pid = 0;
    (nl->daddr).nl_groups = 0;

    nl->nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PLOAD));
    memset(nl->nlh, 0, sizeof(struct nlmsghdr));
    nl->nlh->nlmsg_len = NLMSG_SPACE(MAX_PLOAD);
    nl->nlh->nlmsg_flags = 0;
    nl->nlh->nlmsg_type = 0;
    nl->nlh->nlmsg_seq = 0;
    nl->nlh->nlmsg_pid = (nl->saddr).nl_pid;
}

void nl_recv(nl_socket *nl) {
    // printf("recv begin\n");

    memset(&(nl->u_info), 0, sizeof(nl->u_info));
    nl->len = sizeof(struct sockaddr_nl);
    nl->ret = recvfrom(nl->skfd, &(nl->u_info), sizeof(user_msg_info), 0, (struct sockaddr *)&(nl->daddr), &(nl->len));
    if (!nl->ret) {
        // perror("recv from kernel error\n");
        close(nl->skfd);
        exit(-1);
    }

    // printf("from kernel: %s\n", nl->u_info.msg);
}

void nl_send(char *msg,nl_socket *nl) {
    memcpy(NLMSG_DATA(nl->nlh), msg, strlen(msg));
    nl->ret = sendto(nl->skfd, nl->nlh, nl->nlh->nlmsg_len, 0, (struct sockaddr *)&(nl->daddr), sizeof(struct sockaddr_nl));
    if (!nl->ret) {
        // perror("send to kernel error\n");
        close(nl->skfd);
        exit(-1);
    }
    // printf("to kernel: %s\n", msg);
}

void nl_close(nl_socket *nl) {
    close(nl->skfd);
    free((void *)nl->nlh);
    // printf("Attention: net_link port: %d has been released.\n", nl->port_id);
}
