/*
 *  `rule_db.c`: rules for integrity protection, white-list strategy
 */

#include <utils/rule_db.h>

void _println_db() {
    for (int i = 0; i < 80; i++) {
        printf("-");
    }
    printf("\n");
}

void create_rule(rule *rule, int op, int suid, int sgid, const char *obj) {
    rule->operation = op;
    rule->subject_uid = suid;
    rule->subject_gid = sgid;
    strcpy(rule->object, obj);
}

void set_rule_db_path(rule_db *rule_db, const char *db_path) {
    strcpy(rule_db->db_path, db_path);
    FILE *rule_db_file;
    if (!(rule_db_file = fopen(db_path, "r"))) {
        if (!(rule_db_file = fopen(db_path, "w"))) {
            fprintf(stderr, "cannot open rule_db file\n");
            exit(1);
        }
        fwrite("0\n", sizeof(char), 2, rule_db_file);
    }
    fclose(rule_db_file);
}

void show_rules(rule_db *rule_db) {
    // read number of rules
    FILE *rule_db_file;
    if (!(rule_db_file = fopen(rule_db->db_path, "r"))) {
        fprintf(stderr, "cannot open rule_db file\n");
        exit(1);
    }
    char buf_db[DB_BUFSIZE];
    char buf_rule[RULE_BUFSIZE];
    int len = fread(buf_db, sizeof(char), DB_BUFSIZE, rule_db_file);
    int i = 0;
    while (i < len && buf_db[i] != '\n') {
        i++;
    }
    strncpy(buf_rule, buf_db, i);
    buf_rule[i] = '\0';
    int num_rules;
    sscanf(buf_rule, "%d", &num_rules);

    // print header
    _println_db();
    printf("\t\t\t\t\033[31;1mRULE  DATABASE\033[0m\t\t\t\033[36;1m# rules: %d\033[0m\n", num_rules);
    printf("(white-list strategy) the following operations are allowed by default.\n");
    printf("\033[36m<id>\t<operation>\t<uid>\t<gid>\t<object>\033[0m\n");
    _println_db();
    if (num_rules == 0) {
        _println_db();
        return;
    }

    // read lines of rules
    int rule_op, rule_uid, rule_gid, rule_pid;
    char rule_filename[FILEPATH_MAX];
    int n, j;

    for (n = 0, j = ++i; n < num_rules; n++, j = ++i) {
        while (i < len && buf_db[i] != '\n') {
            i++;
        }
        strncpy(buf_rule, buf_db + j, i - j);
        buf_rule[i - j] = '\0';

        switch (buf_rule[0] - '0') {
            case OP_KILL:
                sscanf(buf_rule, "%d\t%d\t%d\t%d", &rule_op, &rule_uid, &rule_gid, &rule_pid);
                if (rule_uid == 0) {
                    if (rule_gid == 0) {
                        printf("\033[35m%d\tprocess kill\t\t\t pid = %d\n\033[0m", n + 1, rule_pid);
                    } else {
                        printf("\033[35m%d\tprocess kill\t\t%d\t pid = %d\n\033[0m", n + 1, rule_gid, rule_pid);
                    }
                } else {
                    if (rule_gid == 0) {
                        printf("\033[35m%d\tprocess kill\t%d\t\t pid = %d\n\033[0m", n + 1, rule_uid, rule_pid);
                    } else {
                        printf("\033[35m%d\tprocess kill\t%d\t%d\t pid = %d\n\033[0m", n + 1, rule_uid, rule_gid, rule_pid);
                    }
                }
                break;
            case OP_WRITE:
                sscanf(buf_rule, "%d\t%d\t%d\t%s", &rule_op, &rule_uid, &rule_gid, rule_filename);
                if (rule_uid == 0) {
                    if (rule_gid == 0) {
                        printf("\033[32m%d\tfile write\t\t\tpath = %s\n\033[0m", n + 1, rule_filename);
                    } else {
                        printf("\033[32m%d\tfile write\t\t%d\tpath = %s\n\033[0m", n + 1, rule_gid, rule_filename);
                    }
                } else {
                    if (rule_gid == 0) {
                        printf("\033[32m%d\tfile write\t%d\t\tpath = %s\n\033[0m", n + 1, rule_uid, rule_filename);
                    } else {
                        printf("\033[32m%d\tfile write\t%d\t%d\tpath = %s\n\033[0m", n + 1, rule_uid, rule_gid, rule_filename);
                    }
                }
                break;
            case OP_UNLINK:
                sscanf(buf_rule, "%d\t%d\t%d\t%s", &rule_op, &rule_uid, &rule_gid, rule_filename);
                if (rule_uid == 0) {
                    if (rule_gid == 0) {
                        printf("\033[33m%d\tfile delete\t\t\tpath = %s\n\033[0m", n + 1, rule_filename);
                    } else {
                        printf("\033[33m%d\tfile delete\t\t%d\tpath = %s\n\033[0m", n + 1, rule_gid, rule_filename);
                    }
                } else {
                    if (rule_gid == 0) {
                        printf("\033[33m%d\tfile delete\t%d\t\tpath = %s\n\033[0m", n + 1, rule_uid, rule_filename);
                    } else {
                        printf("\033[33m%d\tfile delete\t%d\t%d\tpath = %s\n\033[0m", n + 1, rule_uid, rule_gid, rule_filename);
                    }
                }
                break;
        }
    }
    _println_db();
    fclose(rule_db_file);
}

void add_rule(rule_db *rule_db, rule *rule) {
    // read number of rules
    FILE *rule_db_file;
    if (!(rule_db_file = fopen(rule_db->db_path, "r"))) {
        fprintf(stderr, "cannot open rule_db file\n");
        exit(1);
    }
    char buf_db[DB_BUFSIZE];
    char buf_rule[RULE_BUFSIZE];
    int len = fread(buf_db, sizeof(char), DB_BUFSIZE, rule_db_file);
    int i = 0;
    while (i < len && buf_db[i] != '\n') {
        i++;
    }
    strncpy(buf_rule, buf_db, i);
    buf_rule[i] = '\0';
    int num_rules;
    sscanf(buf_rule, "%d", &num_rules);
    fclose(rule_db_file);

    // rewrite the rule_db (num_rules, old_rules, new rules)
    if (!(rule_db_file = fopen(rule_db->db_path, "w"))) {
        fprintf(stderr, "cannot open rule_db file\n");
        exit(1);
    }
    sprintf(buf_rule, "%d\n", num_rules + 1);
    fwrite(buf_rule, sizeof(char), strlen(buf_rule), rule_db_file);
    fwrite(buf_db + i + 1, sizeof(char), len - i - 1, rule_db_file);
    sprintf(buf_rule, "%d\t%d\t%d\t%s\n", rule->operation, rule->subject_uid, rule->subject_gid, rule->object);
    fwrite(buf_rule, sizeof(char), strlen(buf_rule), rule_db_file);
    fclose(rule_db_file);
}

void delete_rule(rule_db *rule_db, unsigned rule_id) {
    if (rule_id == 0) {
        fprintf(stderr, "[WARNING] rule_id %u is illegal, cannot delete\n", rule_id);
        return;
    }
    // read number of rules
    FILE *rule_db_file;
    if (!(rule_db_file = fopen(rule_db->db_path, "r"))) {
        fprintf(stderr, "cannot open rule_db file\n");
        exit(1);
    }
    char buf_db[DB_BUFSIZE];
    char buf_rule[RULE_BUFSIZE];
    int len = fread(buf_db, sizeof(char), DB_BUFSIZE, rule_db_file);
    int i = 0;
    while (i < len && buf_db[i] != '\n') {
        i++;
    }
    strncpy(buf_rule, buf_db, i);
    buf_rule[i] = '\0';
    int num_rules;
    sscanf(buf_rule, "%d", &num_rules);
    fclose(rule_db_file);

    if (rule_id > num_rules) {
        fprintf(stderr, "[WARNING] rule_id %u is illegal, cannot delete\n", rule_id);
        return;
    }

    // rewrite the rule_db (num_rules, old_rules, new rules)
    if (!(rule_db_file = fopen(rule_db->db_path, "w"))) {
        fprintf(stderr, "cannot open rule_db file\n");
        exit(1);
    }
    sprintf(buf_rule, "%d\n", num_rules - 1);
    fwrite(buf_rule, sizeof(char), strlen(buf_rule), rule_db_file);

    int j = i++;
    while (rule_id > 1) {
        while (i < len && buf_db[i] != '\n') {
            i++;
        }
        i++;
        rule_id--;
    }
    fwrite(buf_db + j, sizeof(char), i - j - 1, rule_db_file);
    while (i < len && buf_db[i] != '\n') {
        i++;
    }
    i++;
    fwrite(buf_db + i, sizeof(char), len - i, rule_db_file);
    fclose(rule_db_file);
}

void clear_rules(rule_db *rule_db) {
    FILE *rule_db_file;
    if (!(rule_db_file = fopen(rule_db->db_path, "w"))) {
        fprintf(stderr, "cannot open rule_db file\n");
        exit(1);
    }
    fwrite("0\n", sizeof(char), 2, rule_db_file);
    fclose(rule_db_file);
}

int check_kill(rule_db *rule_db, kill_msg *kill_msg) {
    FILE *rule_db_file;
    if (!(rule_db_file = fopen(rule_db->db_path, "r"))) {
        fprintf(stderr, "cannot open rule_db file\n");
        exit(1);
    }
    char buf_db[DB_BUFSIZE];
    char buf_rule[RULE_BUFSIZE];
    int rule_op, rule_uid, rule_gid, rule_pid;
    int len = fread(buf_db, sizeof(char), DB_BUFSIZE, rule_db_file);
    int i = 0;
    while (i < len && buf_db[i] != '\n') {
        i++;
    }
    strncpy(buf_rule, buf_db, i);
    buf_rule[i] = '\0';
    int num_rules;
    sscanf(buf_rule, "%d", &num_rules);
    fclose(rule_db_file);
    int n, j;

    for (n = 0, j = ++i; n < num_rules; n++, j = ++i) {
        while (i < len && buf_db[i] != '\n') {
            i++;
        }
        strncpy(buf_rule, buf_db + j, i - j);
        buf_rule[i - j] = '\0';
        if (buf_rule[0] - '0' == OP_KILL) {
            sscanf(buf_rule, "%d\t%d\t%d\t%d", &rule_op, &rule_uid, &rule_gid, &rule_pid);
            if (rule_pid == kill_msg->pid) {
                if (rule_uid == 0 || rule_uid == kill_msg->uid) {
                    if (rule_gid == 0 || rule_gid == kill_msg->gid) {
                        return 1;
                    }
                }
            }
        }
    }
    return 0;
}

int check_write(rule_db *rule_db, write_msg *write_msg) {
    FILE *rule_db_file;
    if (!(rule_db_file = fopen(rule_db->db_path, "r"))) {
        fprintf(stderr, "cannot open rule_db file\n");
        exit(1);
    }
    char buf_db[DB_BUFSIZE];
    char buf_rule[RULE_BUFSIZE];
    int rule_op, rule_uid, rule_gid;
    char rule_filename[FILEPATH_MAX];
    char rule_filename_swp[FILEPATH_MAX];  // vim write
    char rule_filename_swo[FILEPATH_MAX];  // vim write
    int len = fread(buf_db, sizeof(char), DB_BUFSIZE, rule_db_file);
    int i = 0;
    while (i < len && buf_db[i] != '\n') {
        i++;
    }
    strncpy(buf_rule, buf_db, i);
    buf_rule[i] = '\0';
    int num_rules;
    sscanf(buf_rule, "%d", &num_rules);
    fclose(rule_db_file);
    int n, j;

    for (n = 0, j = ++i; n < num_rules; n++, j = ++i) {
        while (i < len && buf_db[i] != '\n') {
            i++;
        }
        strncpy(buf_rule, buf_db + j, i - j);
        buf_rule[i - j] = '\0';
        if (buf_rule[0] - '0' == OP_WRITE) {
            sscanf(buf_rule, "%d\t%d\t%d\t%s", &rule_op, &rule_uid, &rule_gid, rule_filename);
            // only allow write using vim
            int k = strlen(rule_filename) - 1;
            while (k >= 0 && rule_filename[k] != '/') {
                k--;
            }
            strncpy(rule_filename_swp, rule_filename, k);
            rule_filename_swp[k] = '/';
            rule_filename_swp[k + 1] = '.';
            strncpy(rule_filename_swp + k + 2, rule_filename + k + 1, strlen(rule_filename) - k);
            strcpy(rule_filename_swo, rule_filename_swp);
            strcpy(rule_filename_swp + strlen(rule_filename) + 1, ".swp");
            strcpy(rule_filename_swo + strlen(rule_filename) + 1, ".swo");
            //printf("%s\n", rule_filename_swp);
            //printf("%s\n", rule_filename_swo);
            // end
            if (!strcmp(rule_filename, write_msg->filename) ||
                !strcmp(rule_filename_swp, write_msg->filename) ||
                !strcmp(rule_filename_swo, write_msg->filename)) {
                if (rule_uid == 0 || rule_uid == write_msg->uid) {
                    if (rule_gid == 0 || rule_gid == write_msg->gid) {
                        return 1;
                    }
                }
            }
        }
    }
    return 0;
}

int check_unlink(rule_db *rule_db, unlink_msg *unlink_msg) {
    FILE *rule_db_file;
    if (!(rule_db_file = fopen(rule_db->db_path, "r"))) {
        fprintf(stderr, "cannot open rule_db file\n");
        exit(1);
    }
    char buf_db[DB_BUFSIZE];
    char buf_rule[RULE_BUFSIZE];
    int rule_op, rule_uid, rule_gid;
    char rule_filename[FILEPATH_MAX];
    int len = fread(buf_db, sizeof(char), DB_BUFSIZE, rule_db_file);
    int i = 0;
    while (i < len && buf_db[i] != '\n') {
        i++;
    }
    strncpy(buf_rule, buf_db, i);
    buf_rule[i] = '\0';
    int num_rules;
    sscanf(buf_rule, "%d", &num_rules);
    fclose(rule_db_file);
    int n, j;

    for (n = 0, j = ++i; n < num_rules; n++, j = ++i) {
        while (i < len && buf_db[i] != '\n') {
            i++;
        }
        strncpy(buf_rule, buf_db + j, i - j);
        buf_rule[i - j] = '\0';
        if (buf_rule[0] - '0' == OP_UNLINK) {
            sscanf(buf_rule, "%d\t%d\t%d\t%s", &rule_op, &rule_uid, &rule_gid, rule_filename);
            if (!strcmp(rule_filename, unlink_msg->filename)) {
                if (rule_uid == 0 || rule_uid == unlink_msg->uid) {
                    if (rule_gid == 0 || rule_gid == unlink_msg->gid) {
                        return 1;
                    }
                }
            }
        }
    }
    return 0;
}
