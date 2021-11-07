/*
 *  `logger.c`: system logging information persisted to disk
 */

#include <utils/logger.h>

void set_log_path(logger *logger, const char *log_path) {
    strcpy(logger->log_path, log_path);
    FILE *log_file;
    if (!(log_file = fopen(log_path, "w"))) {
        fprintf(stderr, "cannot create log file\n");
        exit(1);
    }
    fclose(log_file);
}

void logging(logger *logger, time_t timestamp, int level, char *message) {
    FILE *log_file;
    if (!(log_file = fopen(logger->log_path, "a"))) {
        fprintf(stderr, "cannot open log file\n");
        exit(1);
    }
    char *timestamp_h = asctime(localtime(&timestamp));
    fwrite(timestamp_h, sizeof(char), strlen(timestamp_h) - 1, log_file);
    switch (level) {
        case LOG_LEVEL_INFO:
            fwrite("    [INFO] ", sizeof(char), strlen("    [INFO] "), log_file); break;
        case LOG_LEVEL_WARNING:
            fwrite(" [WARNING] ", sizeof(char), strlen(" [WARNING] "), log_file); break;
        case LOG_LEVEL_DANGER:
            fwrite("  [DANGER] ", sizeof(char), strlen("  [DANGER] "), log_file); break;
    }
    fwrite(message, sizeof(char), strlen(message), log_file);
    fwrite("\n", sizeof(char), 1, log_file);
    fclose(log_file);
}

void show_log(logger *logger) {
    FILE *log_file;
    if (!(log_file = fopen(logger->log_path, "r"))) {
        fprintf(stderr, "cannot open log file\n");
        exit(1);
    }
    char buf[BUFSIZE_LOG];
    int len;
    while ((len = fread(buf, sizeof(char), BUFSIZE_LOG, log_file)) > 0) {
        buf[len] = '\0';
        printf("%s", buf);
    }
    fclose(log_file);
}

void clear_log(logger *logger) {
    FILE *log_file;
    if (!(log_file = fopen(logger->log_path, "w"))) {
        fprintf(stderr, "cannot create log file\n");
        exit(1);
    }
    fclose(log_file);
}
