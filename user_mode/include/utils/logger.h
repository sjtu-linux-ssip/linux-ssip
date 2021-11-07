/*
 *  `logger.h`: system logging information persisted to disk
 */

#ifndef USER_MODE_LOGGER_H
#define USER_MODE_LOGGER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define FILEPATH_LEN 128
#define BUFSIZE_LOG 128

#define LOG_LEVEL_INFO 0
#define LOG_LEVEL_WARNING 1
#define LOG_LEVEL_DANGER 2

typedef struct {
    char log_path[FILEPATH_LEN];
} logger;

/* set log path of the logger, and create an empty log file in the log_path */
void set_log_path(logger *logger, const char *log_path);

/* logging function, append the logging message in a new line */
void logging(logger *logger, time_t timestamp, int level, char *message);

/* show log */
void show_log(logger *logger);

/* clear log */
void clear_log(logger *logger);

#endif //USER_MODE_LOGGER_H
