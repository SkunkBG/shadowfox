#ifndef SHADOWFOX_LOG_H
#define SHADOWFOX_LOG_H

typedef enum {
    LOG_OFF = 0,
    LOG_ERROR,
    LOG_WARN,
    LOG_INFO,
    LOG_DEBUG
} log_level_t;

/* path == NULL или "" — писать в stderr. Возвращает 0 при успехе. */
int  log_open(const char *path, log_level_t level);
void log_close(void);
void log_reopen(void);            /* после ротации, по SIGHUP */
void log_set_level(log_level_t level);
log_level_t log_level_from_string(const char *s);

void log_msg(log_level_t level, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

#define log_error(...) log_msg(LOG_ERROR, __VA_ARGS__)
#define log_warn(...)  log_msg(LOG_WARN,  __VA_ARGS__)
#define log_info(...)  log_msg(LOG_INFO,  __VA_ARGS__)
#define log_debug(...) log_msg(LOG_DEBUG, __VA_ARGS__)

#endif /* SHADOWFOX_LOG_H */
