#include "config.h"
#include "shadowfox.h"
#include "util.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

void config_defaults(config_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    str_copy(cfg->conf_file, sizeof(cfg->conf_file), DEFAULT_CONF_FILE);
    str_copy(cfg->pid_file,  sizeof(cfg->pid_file),  DEFAULT_PID_FILE);
    str_copy(cfg->log_file,  sizeof(cfg->log_file),  DEFAULT_LOG_FILE);
    str_copy(cfg->conf_dir, sizeof(cfg->conf_dir), DEFAULT_CONF_DIR);
    /* Мост локальной сети: через него идут DNS-ответы клиентам. */
    str_copy(cfg->capture_iface, sizeof(cfg->capture_iface), "br0");
    cfg->log_level  = LOG_INFO;
    cfg->foreground = 0;
    cfg->auto_start = 1;
    cfg->ipv6       = 1;
    /* Заводить политики на роутере и сохранять его конфигурацию — это
       изменение настроек устройства, а не наша внутренняя кухня.
       Молча так делать нельзя, поэтому по умолчанию выключено. */
    cfg->create_policy = 0;

    str_copy(cfg->policy, sizeof(cfg->policy), "ShadowFox");
    str_copy(cfg->proxy_iface, sizeof(cfg->proxy_iface), "Proxy1");
    /* 1300 у HydraRoute — берём соседний, чтобы не столкнуться. */
    cfg->socks_port = 1301;
    str_copy(cfg->nodes_file, sizeof(cfg->nodes_file),
             DEFAULT_CONF_DIR "/nodes.txt");
    str_copy(cfg->xray_config, sizeof(cfg->xray_config),
             DEFAULT_CONF_DIR "/xray.json");
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

    if (!strcasecmp(key, "confDir")) {
        str_copy(cfg->conf_dir, sizeof(cfg->conf_dir), value);
        return 0;
    }

    if (!strcasecmp(key, "interface")) {
        str_copy(cfg->capture_iface, sizeof(cfg->capture_iface), value);
        return 0;
    }

    if (!strcasecmp(key, "ipv6")) {
        cfg->ipv6 = parse_bool(value, cfg->ipv6);
        return 0;
    }

    if (!strcasecmp(key, "policy")) {
        str_copy(cfg->policy, sizeof(cfg->policy), value);
        return 0;
    }

    if (!strcasecmp(key, "proxyInterface")) {
        str_copy(cfg->proxy_iface, sizeof(cfg->proxy_iface), value);
        return 0;
    }

    if (!strcasecmp(key, "socksPort")) {
        cfg->socks_port = atoi(value);
        return 0;
    }

    if (!strcasecmp(key, "nodesFile")) {
        str_copy(cfg->nodes_file, sizeof(cfg->nodes_file), value);
        return 0;
    }

    if (!strcasecmp(key, "xrayConfig")) {
        str_copy(cfg->xray_config, sizeof(cfg->xray_config), value);
        return 0;
    }

    if (!strcasecmp(key, "xrayBin")) {
        str_copy(cfg->xray_bin, sizeof(cfg->xray_bin), value);
        return 0;
    }

    if (!strcasecmp(key, "createPolicy")) {
        cfg->create_policy = parse_bool(value, cfg->create_policy);
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
        if (!strcmp(argv[i], "--no-fragment") ||
            !strcmp(argv[i], "--fragment") ||
            !strcmp(argv[i], "--dry-run") ||
            !strcmp(argv[i], "--setup-proxy") ||
            !strcmp(argv[i], "-s") || !strcmp(argv[i], "--status")) continue;

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
        "autoStart=yes\n"
        "\n"
        "# Где лежат domain.conf и ip.list.\n"
        "confDir=%s\n"
        "\n"
        "# Интерфейс, на котором ловим DNS-ответы. Обычно мост локальной\n"
        "# сети. Пустое значение — слушать все интерфейсы.\n"
        "interface=%s\n"
        "\n"
        "# Обслуживать ли IPv6.\n"
        "ipv6=yes\n"
        "\n"
        "# Разрешить демону заводить недостающие политики на роутере и\n"
        "# сохранять его конфигурацию. Это изменение настроек устройства,\n"
        "# поэтому по умолчанию выключено: политику создаёт администратор.\n"
        "createPolicy=no\n"
        "\n"
        "# Свой экземпляр Xray и своё прокси-подключение в Keenetic.\n"
        "# nodesFile — файл со ссылками vless:// либо подпиской. Пока его\n"
        "# нет, свой Xray не запускается, и маршрутизация работает через\n"
        "# то подключение, которое настроено вручную.\n"
        "nodesFile=%s\n"
        "xrayConfig=%s\n"
        "socksPort=%d\n"
        "proxyInterface=%s\n"
        "policy=%s\n",
        cfg.log_file, cfg.pid_file, cfg.conf_dir, cfg.capture_iface,
        cfg.nodes_file, cfg.xray_config, cfg.socks_port,
        cfg.proxy_iface, cfg.policy);

    fclose(f);
    return 0;
}
