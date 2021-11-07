echo "\033[36;1mLaunching Linux-SSIP UI for Linux Kernel v5.4.0 ...\033[0m"
if [ -d "../user_mode/build" ]; then
    cd ../user_mode/build
    ./user_interface
else
    echo "\033[31mCannot run UI: Linux-SSIP has not been installed.\033[0m"
fi
