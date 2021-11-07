/*
 *  `rule_db.h`: rules for integrity protection, white-list strategy
 */

#ifndef USER_MODE_RULE_DB_H
#define USER_MODE_RULE_DB_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <utils/message.h>

#define FILEPATH_MAX 256
#define DB_BUFSIZE 2048
#define RULE_BUFSIZE 512

#define OP_KILL 0
#define OP_WRITE 1
#define OP_UNLINK 2

typedef struct {
    // operation, what to allow
    int operation;
    // operation subject
    // root is always allowed
    // 0: all users/groups are allowed
    // >0: specific user/group is allowed
    int subject_uid;
    int subject_gid;
    // operation object
    // kill - pid, write/delete - filename
    char object[FILEPATH_MAX];
} rule;

typedef struct {
    char db_path[FILEPATH_MAX];
} rule_db;

/* create a rule */
void create_rule(rule *rule, int op, int suid, int sgid, const char *obj);

/* set rule_db path */
void set_rule_db_path(rule_db *rule_db, const char *db_path);

/* print rules in db in a formatted way */
void show_rules(rule_db *rule_db);

/* add a rule */
void add_rule(rule_db *rule_db, rule *rule);

/* delete a rule */
void delete_rule(rule_db *rule_db, unsigned rule_id);

/* clear all rules */
void clear_rules(rule_db *rule_db);

// check whether an operation is allowed (kill/write/unlink)
// return 1 if allowed, else 0
int check_kill(rule_db *rule_db, kill_msg *kill_msg);
int check_write(rule_db *rule_db, write_msg *write_msg);
int check_unlink(rule_db *rule_db, unlink_msg *unlink_msg);

#endif //USER_MODE_RULE_DB_H
