/*
 *  `kill_daemon.c`: receive kill information from kernel
 *  and process kill message
 */

#include <daemon.h>

int main() {
    nl_socket nl_kill;
    nl_init(KILL_SUBDAEMON_PORT, &nl_kill);
    kill_msg kill_msg;
    rule_db rule_db;
    logger logger_kill;
    set_rule_db_path(&rule_db, "rules/rule.db");
    set_log_path(&logger_kill, "logs/kill.log");

    while (1) {
        nl_recv(&nl_kill);
        raw2kill(nl_kill.u_info.msg, &kill_msg);
        if (check_kill(&rule_db, &kill_msg)) {
            // allow the operation
            nl_send(ALLOW_MSG, &nl_kill);
        } else {
            // deny the operation
            nl_send(DENY_MSG, &nl_kill);
            char message[LOG_LEN];
            sprintf(message, "protect process %d from killed by ...", kill_msg.pid);
            logging(&logger_kill, time(NULL), LOG_LEVEL_DANGER, message);
        }
    }
}
