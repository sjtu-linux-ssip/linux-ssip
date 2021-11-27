echo "\033[36;1mLaunching Linux-SSIP daemons and kernel modules for Linux Kernel v5.4.0 ...\033[0m"
if [ -d "../user_mode/build" ]; then
    echo "\033[32;1mLaunching kernel-mode part ...\033[0m"
    cd ../kernel_mode/kill_hook && insmod mod_sys_kill_hook.ko
    cd ../write_hook && insmod mod_sys_openat_write_hook.ko
    cd ../unlink_hook && insmod mod_sys_unlinkat_hook.ko
    echo "\033[32;1mLaunching user-mode part ...\033[0m"
    cd ../../user_mode/build
    ./core_daemon
    cd ../../scripts
    echo "\033[36;1mSuccessfully launched Linux-SSIP for Linux Kernel v5.4.0\033[0m"
else
    echo "\033[31mCannot run daemons and kernel modules: Linux-SSIP has not been installed.\033[0m"
fi
