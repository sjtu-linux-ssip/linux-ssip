/*
 *  `daemon_launch.c`: launch kill/write/unlink daemons through forking
 */

#include <daemon_launch.h>

int main() {
    pid_t pid_kill, pid_write, pid_unlink;

    while ((pid_kill = fork()) == -1);
    if (!pid_kill) {
        /* kill_daemon */
        char *argv[] = {KILL_DAEMON_PATH, (char*)0};
        execv(KILL_DAEMON_PATH, argv);
        fprintf(stderr, "cannot execute kill daemons\n");
        exit(1);
        /* kill_daemon_end */
    } else {
        while ((pid_write = fork()) == -1);
        if (!pid_write) {
            /* write_daemon */
            char *argv[] = {WRITE_DAEMON_PATH, (char*)0};
            execv(WRITE_DAEMON_PATH, argv);
            fprintf(stderr, "cannot execute write daemons\n");
            exit(1);
            /* write_daemon_end */
        } else {
            while ((pid_unlink = fork()) == -1);
            if (!pid_unlink) {
                /* unlink_daemon */
                char *argv[] = {UNLINK_DAEMON_PATH, (char*)0};
                execv(UNLINK_DAEMON_PATH, argv);
                fprintf(stderr, "cannot execute unlink daemons\n");
                exit(1);
                /* unlink_daemon_end */
            }
        }
    }
    return 0;
}
