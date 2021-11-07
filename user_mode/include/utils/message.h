/*
 *  `message.h`: conversions between netlink raw message and formatted message
 */

#ifndef USER_MODE_MESSAGE_H
#define USER_MODE_MESSAGE_H

#include <stdio.h>
#include <string.h>

#define MAX_FILE_NAME 256
#define KILL_PARSE_FORMAT "%d&%d&%d"
#define WRITE_PARSE_FORMAT "%d@%d@%s"
#define UNLINK_PARSE_FORMAT "%d#%d#%s"

// kill message type
typedef struct {
    int uid;  // possible attacker user
    int gid;  // possible attacker group
    int pid;  // possible victim process
} kill_msg;

// write message type
typedef struct {
    int uid;  // possible attacker user
    int gid;  // possible attacker group
    char filename[MAX_FILE_NAME];  // possible victim file
} write_msg;

// unlink message type
typedef struct {
    int uid;  // possible attacker user
    int gid;  // possible attacker group
    char filename[MAX_FILE_NAME];  // possible victim file
} unlink_msg;

// constructors
void build_kill_msg(kill_msg *kill_msg, int uid, int gid, int pid);
void build_write_msg(write_msg *write_msg, int uid, int gid, const char *filename);
void build_unlink_msg(unlink_msg *unlink_msg, int uid, int gid, const char *filename);

// message conversions
void raw2kill(char *raw_msg, kill_msg *kill_msg);
void kill2raw(char *raw_msg, kill_msg *kill_msg);
void raw2write(char *raw_msg, write_msg *write_msg);
void write2raw(char *raw_msg, write_msg *write_msg);
void raw2unlink(char *raw_msg, unlink_msg *unlink_msg);
void unlink2raw(char *raw_msg, unlink_msg *unlink_msg);

#endif //USER_MODE_MESSAGE_H
