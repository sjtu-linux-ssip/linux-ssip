echo "\033[36;1mTerminating Linux-SSIP daemons and kernel modules for Linux Kernel v5.4.0 ...\033[0m"
echo "\033[32;1mTerminating user-mode part ...\033[0m"
pkill kill_daemon
pkill write_daemon
pkill unlink_daemon
echo "\033[32;1mTerminating kernel-mode part ...\033[0m"
rmmod mod_sys_kill_hook
rmmod mod_sys_openat_write_hook
rmmod mod_sys_unlinkat_hook
echo "\033[36;1mSuccessfully terminated Linux-SSIP for Linux Kernel v5.4.0\033[0m"
