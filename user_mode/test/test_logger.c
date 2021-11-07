#include <utils/logger.h>

int main() {
    logger logger;
    set_log_path(&logger, "tests/test.log");  // `mkdir` now CANNOT support
    logging(&logger, time(NULL), LOG_LEVEL_INFO, "info log");
    logging(&logger, time(NULL), LOG_LEVEL_WARNING, "warning log");
    logging(&logger, time(NULL), LOG_LEVEL_DANGER, "danger log");
    show_log(&logger);
    return 0;
}

