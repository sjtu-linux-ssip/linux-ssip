/*
 *  `daemon.h`: the daemons processes communicating with kernel
 *  and processing messages
 */

#ifndef USER_MODE_SUB_DAEMON_H
#define USER_MODE_SUB_DAEMON_H

#include <utils/nl_wrapper.h>
#include <utils/message.h>
#include <utils/rule_db.h>
#include <utils/logger.h>

#define KILL_SUBDAEMON_PORT 9095
#define WRITE_SUBDAEMON_PORT 9096
#define UNLINK_SUBDAEMON_PORT 9097

#define ALLOW_MSG "1"
#define DENY_MSG "0"
#define LOG_LEN 512

#endif //USER_MODE_SUB_DAEMON_H
