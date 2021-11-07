echo "\033[36;1mInstalling Linux-SSIP for Linux Kernel v5.4.0 ...\033[0m"
echo "\033[32;1mInstalling kernel-mode part ...\033[0m"
cd ../kernel_mode/kill_hook && make
cd ../write_hook && make
cd ../unlink_hook && make
echo "\033[32;1mInstalling user-mode part ...\033[0m"
cd ../../user_mode
if [ -d "build" ]; then
    rm -r build
fi
mkdir build && cd build
mkdir rules logs tests
cmake .. && make
cd ../../scripts
echo "\033[36;1mSuccessfully installed Linux-SSIP for Linux Kernel v5.4.0\033[0m"
