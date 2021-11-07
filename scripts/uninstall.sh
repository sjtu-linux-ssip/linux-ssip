echo "\033[36;1mUninstalling Linux-SSIP for Linux Kernel v5.4.0 ...\033[0m"
echo "\033[32;1mUninstalling kernel-mode part ...\033[0m"
cd ../kernel_mode/kill_hook && make clean
cd ../write_hook && make clean
cd ../unlink_hook && make clean
cd ../..
echo "\033[32;1mUninstalling user-mode part ...\033[0m"
if [ -d "user_mode/build" ]; then
    rm -r user_mode/build
fi
cd scripts
echo "\033[36;1mSuccessfully uninstalled Linux-SSIP for Linux Kernel v5.4.0\033[0m"
