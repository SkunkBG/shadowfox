#include "config.h"
#include "shadowfox.h"
#include "util.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

void config_defaults(config_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    str_copy(cfg->conf_file, sizeof(cfg->conf_file), DEFAULT_CONF_FILE);
    str_copy(cfg->pid_file,  sizeof(cfg->pid_file),  DEFAULT_PID_FILE);
    str_copy(cfg->log_file,  sizeof(cfg->log_file),  DEFAULT_LOG_FILE);
    cfg->log_level  = LOG_INFO;
    cfg->foreground = 0;
    cfg->auto_start = 1;
}

int config_set(config_t *cfg, const char *key, const char *value)
{
    if (!cfg || !key) return -1;

    if (!strcasecmp(key, "pidFile")) {
        str_copy(cfg->pid_file, sizeof(cfg->pid_file), value);
        return 0;
    }

    if (!strcasecmp(key, "logFile")) {
        str_copy(cfg->log_file, sizeof(cfg->log_file), value);
        return 0;
    }

    if (!strcasecmp(key, "log")) {
        cfg->log_level = log_level_from_string(value);
        return 0;
    }

    if (!strcasecmp(key, "autoStart")) {
        cfg->auto_start = parse_bool(value, cfg->auto_start);
        return 0;
    }

    return -1;                          /* неизвестный ключ */
}

int config_apply_args(config_t *cfg, int argc, char **argv)
{
    if (!cfg) return -1;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-f") || !strcmp(argv[i], "--foreground")) {
            cfg->foreground = 1;
            continue;
        }

        /* Разобраны раньше, до чтения файла. */
        if (!strcmp(argv[i], "-c") || !strcmp(argv[i], "--config") ||
            !strcmp(argv[i], "--genconfig") || !strcmp(argv[i], "--link") ||
            !strcmp(argv[i], "--sub") || !strcmp(argv[i], "--socks-port") ||
            !strcmp(argv[i], "--listen")) {
            if (i + 1 < argc) i++;
            continue;
        }
        if (!strcmp(argv[i], "--no-fragment")) continue;

        if (!strncmp(argv[i], "--", 2) && i + 1 < argc &&
            config_set(cfg, argv[i] + 2, argv[i + 1]) == 0) {
            i++;
            continue;
        }

        fprintf(stderr, "неизвестный флаг '%s'\n", argv[i]);
        return -1;
    }

    return 0;
}

int config_load_file(config_t *cfg, const char *path)
{
    if (!cfg || !path || !*path) return -1;

    FILE *f = fopen(path, "r");
    if (!f) {
        /* Файла нет — работаем на дефолтах, это штатная ситуация. */
        return (errno == ENOENT) ? 0 : -1;
    }

    char line[512];
    int  lineno = 0;
    int  bad    = 0;

    while (fgets(line, sizeof(line), f)) {
        lineno++;

        char *s = str_trim(line);
        if (!*s || *s == '#' || *s == ';') continue;

        char *eq = strchr(s, '=');
        if (!eq) {
            fprintf(stderr, "%s:%d: строка без '=': %s\n", path, lineno, s);
            bad++;
            continue;
        }

        *eq = '\0';
        char *key = str_trim(s);
        char *val = str_trim(eq + 1);

        if (config_set(cfg, key, val) != 0) {
            fprintf(stderr, "%s:%d: неизвестный параметр '%s'\n", path, lineno, key);
            bad++;
        }
    }

    fclose(f);
    return bad ? -1 : 0;
}

int config_write_default(const char *path)
{
    if (!path || !*path) return -1;

    config_t cfg;
    config_defaults(&cfg);

    char dir[CFG_PATH_MAX];
    if (str_copy(dir, sizeof(dir), path) == 0) {
        char *slash = strrchr(dir, '/');
        if (slash) { *slash = '\0'; mkdir_p(dir, 0755); }
    }

    FILE *f = fopen(path, "w");
    if (!f) return -1;

    fprintf(f,
        "# Конфигурация " SHADOWFOX_NAME " " VERSION "\n"
        "# Любой параметр доступен и как флаг CLI: --имя значение.\n"
        "# Приоритет: CLI > этот файл > встроенные значения.\n"
        "\n"
        "# Уровень логирования: off | error | warn | info | debug\n"
        "log=info\n"
        "\n"
        "# Файл журнала. Пустое значение — писать в stderr.\n"
        "logFile=%s\n"
        "\n"
        "# PID-файл. По нему ndm-хуки находят демона и шлют SIGUSR1.\n"
        "pidFile=%s\n"
        "\n"
        "# Поднимать маршрутизацию сразу при старте.\n"
        "autoStart=yes\n",
        cfg.log_file, cfg.pid_file);

    fclose(f);
    return 0;
}
