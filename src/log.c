#include "log.h"
#include "util.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

static FILE       *g_fp    = NULL;    /* NULL — пишем в stderr */
static log_level_t g_level = LOG_INFO;
static char        g_path[256];

/* init.d не подхватывает окружение профиля, поэтому TZ демону не
   достаётся и метки времени уходят в UTC, расходясь с часами роутера.
   Entware держит зону в /opt/etc/TZ — читаем оттуда. */
static void adopt_timezone(void)
{
    if (getenv("TZ")) return;

    FILE *f = fopen("/opt/etc/TZ", "r");
    if (!f) return;

    char tz[64];
    if (fgets(tz, sizeof(tz), f)) {
        char *nl = strpbrk(tz, "\r\n");
        if (nl) *nl = '\0';
        if (tz[0]) setenv("TZ", tz, 1);
    }
    fclose(f);
    tzset();
}

static const char *level_name(log_level_t l)
{
    switch (l) {
    case LOG_ERROR: return "ERROR";
    case LOG_WARN:  return "WARN";
    case LOG_INFO:  return "INFO";
    case LOG_DEBUG: return "DEBUG";
    default:        return "?";
    }
}

log_level_t log_level_from_string(const char *s)
{
    if (!s || !*s)              return LOG_INFO;
    if (!strcasecmp(s, "off"))   return LOG_OFF;
    if (!strcasecmp(s, "error")) return LOG_ERROR;
    if (!strcasecmp(s, "warn"))  return LOG_WARN;
    if (!strcasecmp(s, "info"))  return LOG_INFO;
    if (!strcasecmp(s, "debug")) return LOG_DEBUG;
    return LOG_INFO;
}

int log_open(const char *path, log_level_t level)
{
    adopt_timezone();
    g_level = level;
    log_close();

    if (!path || !*path) {
        g_path[0] = '\0';
        return 0;                       /* stderr */
    }

    char dir[256];
    if (str_copy(dir, sizeof(dir), path) == 0) {
        char *slash = strrchr(dir, '/');
        if (slash) { *slash = '\0'; mkdir_p(dir, 0755); }
    }

    g_fp = fopen(path, "a");
    if (!g_fp) {
        g_path[0] = '\0';
        return -1;                      /* откатились на stderr */
    }
    setvbuf(g_fp, NULL, _IOLBF, 0);
    str_copy(g_path, sizeof(g_path), path);
    return 0;
}

void log_close(void)
{
    if (g_fp) { fclose(g_fp); g_fp = NULL; }
}

void log_reopen(void)
{
    if (g_path[0]) log_open(g_path, g_level);
}

void log_set_level(log_level_t level)
{
    g_level = level;
}

void log_msg(log_level_t level, const char *fmt, ...)
{
    if (g_level == LOG_OFF || level > g_level) return;

    FILE *out = g_fp ? g_fp : stderr;

    char      ts[32] = "";
    time_t    now    = time(NULL);
    struct tm tm;
    if (localtime_r(&now, &tm))
        strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S%z", &tm);

    fprintf(out, "%s [%s] ", ts, level_name(level));

    va_list ap;
    va_start(ap, fmt);
    vfprintf(out, fmt, ap);
    va_end(ap);

    fputc('\n', out);
    fflush(out);
}
