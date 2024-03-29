/*
 *  `write_daemon.c`: receive write information from kernel
 *  and process write message
 */

#include <daemon.h>

int main() {
    nl_socket nl_write;
    nl_init(WRITE_DAEMON_PORT, &nl_write, WRITE_NETLINK_FAMILY);
    nl_send(HELLO_MSG, &nl_write);
    write_msg write_msg;
    rule_db rule_db;
    logger logger_write;
    set_rule_db_path(&rule_db, "rules/rule.db");
    set_log_path(&logger_write, "logs/write.log");

    while (1) {
        nl_recv(&nl_write);
        raw2write(nl_write.u_info.msg, &write_msg);
        if (check_write(&rule_db, &write_msg)) {
            // allow the operation
            nl_send(ALLOW_MSG, &nl_write);
        } else {
            // deny the operation
            nl_send(DENY_MSG, &nl_write);
            // only allow write using vim
            int k = strlen(write_msg.filename) - 4;
            write_msg.filename[k--] = '\0';
            while (k >= 0 && write_msg.filename[k] != '/') { k--; } k++;
            while (write_msg.filename[++k] != '\0') { write_msg.filename[k-1] = write_msg.filename[k]; }
            write_msg.filename[k-1] = '\0';
            // end
            char message[LOG_LEN];
            sprintf(message, "protect file %s from written by user(uid: %d), group(gid: %d)",
                write_msg.filename, write_msg.uid, write_msg.gid);
            logging(&logger_write, time(NULL), LOG_LEVEL_DANGER, message);
        }
    }
}
