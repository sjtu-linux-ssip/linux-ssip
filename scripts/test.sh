echo "\033[36;1mTesting user-mode part ...\033[0m"
if [ -d "../user_mode/build" ]; then
    cd ../user_mode/build/
    ./test_message
    ./test_logger
    ./test_rule_db
    cd ../../scripts
    echo "\033[36;1mTest finished\033[0m"
else
    echo "\033[31mCannot run tests: Linux-SSIP has not been installed.\033[0m"
fi
