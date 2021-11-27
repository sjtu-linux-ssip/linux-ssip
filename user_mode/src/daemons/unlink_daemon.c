/*
 *  `unlink_daemon.c`: receive unlink information from kernel
 *  and process unlink message
 */

#include <daemon.h>

int main() {
    nl_socket nl_unlink;
    nl_init(UNLINK_DAEMON_PORT, &nl_unlink, UNLINK_NETLINK_FAMILY);
    nl_send(HELLO_MSG, &nl_unlink);
    unlink_msg unlink_msg;
    rule_db rule_db;
    logger logger_unlink;
    set_rule_db_path(&rule_db, "rules/rule.db");
    set_log_path(&logger_unlink, "logs/unlink.log");

    while (1) {
        nl_recv(&nl_unlink);
        raw2unlink(nl_unlink.u_info.msg, &unlink_msg);
        if (check_unlink(&rule_db, &unlink_msg)) {
            // allow the operation
            nl_send(ALLOW_MSG, &nl_unlink);
        } else {
            // deny the operation
            nl_send(DENY_MSG, &nl_unlink);
            char message[LOG_LEN];
            sprintf(message, "protect file %s from deleted by user(uid: %d), group(gid: %d)",
                unlink_msg.filename, unlink_msg.uid, unlink_msg.gid);
            logging(&logger_unlink, time(NULL), LOG_LEVEL_DANGER, message);
        }
    }
}
