/*
 *  `daemon_launch.h`: launch kill/write/unlink daemons through forking
 */

#ifndef USER_MODE_CORE_DAEMON_H
#define USER_MODE_CORE_DAEMON_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define KILL_SUBDAEMON_PATH "kill_daemon"
#define WRITE_SUBDAEMON_PATH "write_daemon"
#define UNLINK_SUBDAEMON_PATH "unlink_daemon"

#endif //USER_MODE_CORE_DAEMON_H
