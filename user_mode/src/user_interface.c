/*
 *  `user_interface.c`: user command line interface with the software
 */

#include <user_interface.h>

rule_db rule_db_obj;
logger logger_kill, logger_write, logger_unlink;

void _println_ui() {
    for (int i = 0; i < 80; i++) {
        printf("\033[34m*\033[0m");
    }
    printf("\n");
}

void print_help_message() {
    printf("\033[35;1mHelp\033[0m");
    printf("\033[35m on a list of classes of commands:\033[0m\n");
    // rule
    printf("\033[32;1mrule\033[0m\t\tRule database helper.\n");
    printf("\033[32m  rule show  \033[0m  --  show all rules\n");
    printf("\033[32m  rule add   \033[0m  --  add a rule\n");
    printf("\033[32m  rule remove\033[0m  --  remove a rule\n");
    printf("\033[32m  rule clear \033[0m  --  clear all rules\n");
    // log;
    printf("\033[32;1mlog\033[0m\t\tLogger helper.\n");
    printf("\033[32m  log show \033[0m [kill/write/delete]  --  show log information\n");
    printf("\033[32m  log clear\033[0m [kill/write/delete]  --  clear log file\n");
    // q; quit;
    printf("\033[32;1mquit (q)\033[0m\tExit the program.\n");
    // h; help;
    printf("\033[32;1mhelp (h)\033[0m\tPrint this help message.\n");
}

void rule_add() {
    printf("\033[35mNote that we take \033[0m");
    printf("\033[35;1mwhite-list\033[0m");
    printf("\033[35m strategy, the operation is allowed by default.\033[0m\n");

    rule new_rule;
    char user_input[USER_INPUT_MAXSIZE];
    int rule_op, rule_uid, rule_gid;

    // rule operation
    printf("\033[35mPlease type the operation of the rule [\033[0m");
    printf("\033[36;1mkill\033[0m"); printf("\033[35m/\033[0m");
    printf("\033[36;1mwrite\033[0m"); printf("\033[35m/\033[0m");
    printf("\033[36;1mdelete\033[0m"); printf("\033[35m]: \033[0m\n");
    printf("\033[35;1m>>> \033[0m");
    fgets(user_input, USER_INPUT_MAXSIZE, stdin);

    if (strlen(user_input) == 1 || !strcmp(user_input, "q\n") || !strcmp(user_input, "quit\n")) {
        return;
    } else if (!strcmp(user_input, "kill\n")) {
        rule_op = OP_KILL;
    } else if (!strcmp(user_input, "write\n")) {
        rule_op = OP_WRITE;
    } else if (!strcmp(user_input, "delete\n")) {
        rule_op = OP_UNLINK;
    } else {
        printf("\033[31mInvalid rule operation.\033[0m\n");
        return;
    }

    // user id
    printf("\033[35mPlease type the uid of the allowed user (all users: type \"0\") [\033[0m");
    printf("\033[36mtip: \"id <username>\" for the uid\033[0m"); printf("\033[35m]:\033[0m\n");
    printf("\033[35;1m>>> \033[0m");
    scanf("%d", &rule_uid);
    getchar();  // absorb <Enter>

    // group id
    printf("\033[35mPlease type the gid of the allowed group (all groups: type \"0\") [\033[0m");
    printf("\033[36mtip: \"id <groupname>\" for the gid\033[0m"); printf("\033[35m]:\033[0m\n");
    printf("\033[35;1m>>> \033[0m");
    scanf("%d", &rule_gid);
    getchar();  // absorb <Enter>

    // object, and create & add rule
    if (rule_op == OP_KILL) {
        int rule_pid;
        char rule_pid_str[USER_INPUT_MAXSIZE];
        printf("\033[35mPlease type the pid of the allowed process [\033[0m");
        printf("\033[36mtip: \"ps -aux | grep <program>\" for the pid\033[0m"); printf("\033[35m]:\033[0m\n");
        printf("\033[35;1m>>> \033[0m");
        scanf("%d", &rule_pid);
        getchar();  // absorb <Enter>
        sprintf(rule_pid_str, "%d", rule_pid);
        create_rule(&new_rule, rule_op, rule_uid, rule_gid, rule_pid_str);
    } else {
        char rule_filename[USER_INPUT_MAXSIZE];
        printf("\033[35mPlease type the absolute path of the allowed file:\033[0m\n");
        printf("\033[35;1m>>> \033[0m");
        fgets(rule_filename, USER_INPUT_MAXSIZE, stdin);
        rule_filename[strlen(rule_filename) - 1] = '\0';
        create_rule(&new_rule, rule_op, rule_uid, rule_gid, rule_filename);
    }

    add_rule(&rule_db_obj, &new_rule);
    printf("\033[32mSuccessfully added the rule to the database.\033[0m\n");
}

void rule_remove() {
    show_rules(&rule_db_obj);
    printf("\033[35mPlease type the index of the rule that you remove:\033[0m\n");
    printf("\033[35;1m>>> \033[0m");
    int idx;
    scanf("%d", &idx);
    getchar();  // absorb <Enter>
    delete_rule(&rule_db_obj, idx);
    printf("\033[32mSuccessfully removed the rule from the database.\033[0m\n");
}

int parse_line(char *user_input) {
    // return 1 if continue loop, 0 if quit

    // strip spaces
    int len = strlen(user_input) - 1;
    int i = 0, j = len - 1;
    char line[USER_INPUT_MAXSIZE];
    while (user_input[i] == ' ') {
        i++;
    }
    while (user_input[j] == ' ') {
        j--;
    }
    strncpy(line, user_input + i, j - i + 1);
    line[j - i + 1] = '\0';
    len = j - i + 1;

    // empty line
    if (len == 0) {
        return 1;
    }

    // single letter
    if (len == 1) {
        switch (line[0]) {
            case 'h':
                print_help_message();
                return 1;
            case 'q':
                return 0;
        }
    }

    // words
    else {
        if (!strcmp(line, "help")) {
            print_help_message();
            return 1;
        }
        if (!strcmp(line, "quit")) {
            return 0;
        }
        if (!strcmp(line, "rule")) {
            printf("\033[35mPlease type argument for the \"rule\" command, see \"help\" for details.\033[0m\n");
            return 1;
        }
        if (!strcmp(line, "rule show")) {
            show_rules(&rule_db_obj);
            return 1;
        }
        if (!strcmp(line, "rule add")) {
            rule_add();
            return 1;
        }
        if (!strcmp(line, "rule remove")) {
            rule_remove();
            return 1;
        }
        if (!strcmp(line, "rule clear")) {
            clear_rules(&rule_db_obj);
            printf("\033[32mSuccessfully cleared the rules of the database.\033[0m\n");
            return 1;
        }
        if (!strcmp(line, "log")) {
            printf("\033[35mPlease type argument for the \"log\" command, see \"help\" for details.\033[0m\n");
            return 1;
        }
        if (!strcmp(line, "log show")) {
            printf("\033[35mPlease type \"log show [kill/write/delete]\" for the specific log.\033[0m\n");
            return 1;
        }
        if (!strcmp(line, "log show kill")) {
            show_log(&logger_kill);
            return 1;
        }
        if (!strcmp(line, "log show write")) {
            show_log(&logger_write);
            return 1;
        }
        if (!strcmp(line, "log show delete")) {
            show_log(&logger_unlink);
            return 1;
        }
        if (!strcmp(line, "log clear")) {
            printf("\033[35mPlease type \"log clear [kill/write/delete]\" for the specific log.\033[0m\n");
            return 1;
        }
        if (!strcmp(line, "log clear kill")) {
            clear_log(&logger_kill);
            printf("\033[32mSuccessfully cleared the kill logs.\033[0m\n");
            return 1;
        }
        if (!strcmp(line, "log clear write")) {
            clear_log(&logger_write);
            printf("\033[32mSuccessfully cleared the write logs.\033[0m\n");
            return 1;
        }
        if (!strcmp(line, "log clear delete")) {
            clear_log(&logger_unlink);
            printf("\033[32mSuccessfully cleared the delete logs.\033[0m\n");
            return 1;
        }
    }

    printf("\033[31mInvalid Command. Try \"h\" or \"help\".\033[0m\n");
    return 1;
}

int main() {
    printf("\033[35mHello there ~~\033[0m\n"); _println_ui();
    printf("\033[36;1m                 Linux Simple Secure Integrity Protection Tool\033[0m\n");
    printf("Copyright (C) 2021 SJTU Linux SSIP Group, All Rights Reserved.\033[0m\n");
    printf("For help, type \"h\" or \"help\".\n"); _println_ui();
    printf("\033[36;1m>>> \033[0m");

    // initialize rule_db and logs
    set_rule_db_path(&rule_db_obj, "rules/rule.db");
    set_log_path(&logger_kill, "logs/kill.log");
    set_log_path(&logger_write, "logs/write.log");
    set_log_path(&logger_unlink, "logs/unlink.log");

    // interaction loop
    char user_input[USER_INPUT_MAXSIZE];

    while (fgets(user_input, USER_INPUT_MAXSIZE, stdin)) {
        if (!parse_line(user_input)) break;
        printf("\033[36;1m>>> \033[0m");
    }

    _println_ui(); printf("\033[35mBye there ~~\033[0m\n");
    return 0;
}
