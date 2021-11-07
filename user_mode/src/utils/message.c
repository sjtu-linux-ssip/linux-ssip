/*
 *  `message.c`: conversions between netlink raw message and formatted message
 */

#include <utils/message.h>

void build_kill_msg(kill_msg *kill_msg, int uid, int gid, int pid) {
    kill_msg->uid = uid;
    kill_msg->gid = gid;
    kill_msg->pid = pid;
}

void build_write_msg(write_msg *write_msg, int uid, int gid, const char *filename) {
    write_msg->uid = uid;
    write_msg->gid = gid;
    strcpy(write_msg->filename, filename);
}

void build_unlink_msg(unlink_msg *unlink_msg, int uid, int gid, const char *filename) {
    unlink_msg->uid = uid;
    unlink_msg->gid = gid;
    strcpy(unlink_msg->filename, filename);
}

void raw2kill(char *raw_msg, kill_msg *kill_msg) {
    sscanf(raw_msg, KILL_PARSE_FORMAT, &(kill_msg->uid), &(kill_msg->gid), &(kill_msg->pid));
}

void kill2raw(char *raw_msg, kill_msg *kill_msg) {
    sprintf(raw_msg, KILL_PARSE_FORMAT, kill_msg->uid, kill_msg->gid, kill_msg->pid);
}

void raw2write(char *raw_msg, write_msg *write_msg) {
    sscanf(raw_msg, WRITE_PARSE_FORMAT, &(write_msg->uid), &(write_msg->gid), write_msg->filename);
}

void write2raw(char *raw_msg, write_msg *write_msg) {
    sprintf(raw_msg, WRITE_PARSE_FORMAT, write_msg->uid, write_msg->gid, write_msg->filename);
}

void raw2unlink(char *raw_msg, unlink_msg *unlink_msg) {
    sscanf(raw_msg, UNLINK_PARSE_FORMAT, &(unlink_msg->uid), &(unlink_msg->gid), unlink_msg->filename);
}

void unlink2raw(char *raw_msg, unlink_msg *unlink_msg) {
    sprintf(raw_msg, UNLINK_PARSE_FORMAT, unlink_msg->uid, unlink_msg->gid, unlink_msg->filename);
}