cmake_minimum_required(VERSION 3.10.2)
project(user_mode C)

set(CMAKE_C_STANDARD 99)

include_directories(include)

set(USER_INTERFACE_SRC src/user_interface.c src/utils/logger.c src/utils/rule_db.c)
set(CORE_DAEMON_SRC src/daemon_launch.c)
set(KILL_DAEMON_SRC src/daemons/kill_daemon.c src/utils/nl_wrapper.c src/utils/rule_db.c src/utils/logger.c src/utils/message.c)
set(WRITE_DAEMON_SRC src/daemons/write_daemon.c src/utils/nl_wrapper.c src/utils/rule_db.c src/utils/logger.c src/utils/message.c)
set(UNLINK_DAEMON_SRC src/daemons/unlink_daemon.c src/utils/nl_wrapper.c src/utils/rule_db.c src/utils/logger.c src/utils/message.c)

set(TEST_LOGGER_SRC test/test_logger.c src/utils/logger.c)
set(TEST_RULE_DB_SRC test/test_rule_db.c src/utils/rule_db.c src/utils/message.c)
set(TEST_MESSAGE_SRC test/test_message.c src/utils/message.c)

add_executable(user_interface ${USER_INTERFACE_SRC})
add_executable(core_daemon ${CORE_DAEMON_SRC})
add_executable(kill_daemon ${KILL_DAEMON_SRC})
add_executable(write_daemon ${WRITE_DAEMON_SRC})
add_executable(unlink_daemon ${UNLINK_DAEMON_SRC})

add_executable(test_logger ${TEST_LOGGER_SRC})
add_executable(test_rule_db ${TEST_RULE_DB_SRC})
add_executable(test_message ${TEST_MESSAGE_SRC})
