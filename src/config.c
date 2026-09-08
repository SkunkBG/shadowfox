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
    /* Сутки. Домен, который перестали резолвить, выпадает сам, и набор
       не копит адреса, давно переехавшие к другим сервисам. */
    cfg->ipset_timeout = 86400;

    /* По умолчанию включён: без него остаются слепые зоны, которые
       снаружи выглядят как «правило настроено, а сайт идёт мимо».
       Выключатель оставлен на случай, когда захват на 443 мешает. */
    cfg->sni_capture   = 1;
    str_copy(cfg->probe_url, sizeof(cfg->probe_url), "http://www.gstatic.com/generate_204");

    /* Фрагментация включена (действует только на обычный TLS, см.
       xraycfg.c). Отпечаток по умолчанию не перекрываем — берётся из
       ссылки, запасной chrome; перекрытие остаётся ручкой для разбора
       полётов. Ключ noise принимается и игнорируется: шум убран, а
       старые конфиги ругаться не должны. */
    cfg->fragment      = 1;
    cfg->fingerprint[0] = '\0';

    cfg->web_enabled = 1;
    /* 2000 занят hrweb, 8080 у MagiTrickle, 92 был у neofit. */
    cfg->web_port    = 8090;
    /* Вход проверяется у веб-сервера роутера. Порт вынесен в настройку:
       его можно сменить, и тогда вход перестал бы работать молча. */
    cfg->router_port = 80;
    str_copy(cfg->web_proxy, sizeof(cfg->web_proxy), "shadowfox");

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

    if (!strcasecmp(key, "web")) {
        cfg->web_enabled = parse_bool(value, cfg->web_enabled);
        return 0;
    }

    if (!strcasecmp(key, "webPort")) {
        cfg->web_port = atoi(value);
        return 0;
    }

    if (!strcasecmp(key, "routerHost")) {
        str_copy(cfg->router_host, sizeof(cfg->router_host), value);
        return 0;
    }

    if (!strcasecmp(key, "routerPort")) {
        cfg->router_port = atoi(value);
        return 0;
    }

    if (!strcasecmp(key, "webBind")) {
        str_copy(cfg->web_bind, sizeof(cfg->web_bind), value);
        return 0;
    }

    if (!strcasecmp(key, "webToken")) {
        str_copy(cfg->web_token, sizeof(cfg->web_token), value);
        return 0;
    }

    if (!strcasecmp(key, "webProxy")) {
        str_copy(cfg->web_proxy, sizeof(cfg->web_proxy), value);
        return 0;
    }

    if (!strcasecmp(key, "ipsetTimeout")) {
        cfg->ipset_timeout = atoi(value);
        return 0;
    }

    if (!strcasecmp(key, "fragment")) {
        cfg->fragment = parse_bool(value, cfg->fragment);
        return 0;
    }

    if (!strcasecmp(key, "noise")) {
        return 0;   /* устаревший ключ, см. config_defaults */
    }

    if (!strcasecmp(key, "fingerprint")) {
        str_copy(cfg->fingerprint, sizeof(cfg->fingerprint), value);
        return 0;
    }

    if (!strcasecmp(key, "sniCapture")) {
        cfg->sni_capture = parse_bool(value, cfg->sni_capture);
        return 0;
    }

    if (!strcasecmp(key, "tunnelProbe")) {
        /* «no» и пустое — не проверять. */
        if (!value[0] || !parse_bool(value, 1))
            cfg->probe_url[0] = '\0';
        else
            str_copy(cfg->probe_url, sizeof(cfg->probe_url), value);
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
            !strcmp(argv[i], "--setup-web") ||
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
        "# Сколько секунд живёт адрес в наборе. Домен, который перестали\n"
        "# резолвить, выпадает сам, и набор не копит адреса, давно\n"
        "# переехавшие к другим сервисам. 0 отключает старение.\n"
        "ipsetTimeout=86400\n"
        "\n"
        "# Веб-интерфейс: http://<адрес роутера>:8090\n"
        "web=yes\n"
        "webPort=8090\n"
        "# Веб-сервер роутера: по нему проверяется логин с паролем.\n"
        "# Адрес пустой — берётся адрес на интерфейсе выше. Петля не\n"
        "# годится: на 127.0.0.1 роутер отвечает отказом по уровню\n"
        "# безопасности, вход разрешён только с адреса сети.\n"
        "routerHost=\n"
        "routerPort=80\n"
        "\n"
        "# Адрес, на котором слушать. Пусто — адрес интерфейса локальной\n"
        "# сети. Слушать 0.0.0.0 нельзя.\n"
        "webBind=\n"
        "\n"
        "# Необязательный токен: с ним страница требует ?token=... в\n"
        "# адресе. Для доступа снаружи он не нужен — там пароль от\n"
        "# роутера спрашивает сам роутер, см. shadowfoxd --setup-web\n"
        "webToken=\n"
        "\n"
        "# Имя записи в прокси роутера для доступа к странице снаружи\n"
        "# через KeenDNS; заводится кнопкой на странице.\n"
        "webProxy=%s\n"
        "\n"
        "# Свой экземпляр Xray и своё прокси-подключение в Keenetic.\n"
        "# nodesFile — файл со ссылками vless:// либо подпиской. Пока его\n"
        "# нет, свой Xray не запускается, и маршрутизация работает через\n"
        "# то подключение, которое настроено вручную.\n"
        "nodesFile=%s\n"
        "xrayConfig=%s\n"
        "# Путь к ядру. Пусто — искать самим: сначала свою сборку\n"
        "# /opt/sbin/shadowfox-xray, потом штатный xray в PATH.\n"
        "xrayBin=%s\n"
        "socksPort=%d\n"
        "proxyInterface=%s\n"
        "policy=%s\n"
        "\n"
        "# Чтение имени сервера из TLS ClientHello. Закрывает то, чего не\n"
        "# видит перехват DNS: тёплый кеш устройства, свой DoH у клиента,\n"
        "# зашитый в приложении адрес. Требует пакет conntrack, чтобы\n"
        "# оборвать соединение, успевшее уйти мимо туннеля.\n"
        "sniCapture=%s\n"
        "\n"
        "# Адрес для ручной проверки туннеля насквозь — по кнопке на\n"
        "# странице, одним запросом. Автоматической проверки нет и не\n"
        "# будет: ровный ритм одинаковых запросов выдаёт туннель\n"
        "# провайдеру. Живость туннеля демон видит пассивно, по сокетам\n"
        "# ядра. «no» — убрать и кнопку.\n"
        "tunnelProbe=%s\n"
        "\n"
        "# Устойчивость к DPI. fragment режет TLS ClientHello у обычного TLS;\n"
        "# для Reality не применяется — там имя сервера открытое по замыслу.\n"
        "# fingerprint перекрывает отпечаток uTLS из ссылки; пусто — брать\n"
        "# из ссылки, а если и там нет — chrome, как у самого ядра.\n"
        "fragment=%s\n"
        "fingerprint=%s\n",
        cfg.log_file, cfg.pid_file, cfg.conf_dir, cfg.capture_iface,
        cfg.web_proxy,
        cfg.nodes_file, cfg.xray_config, cfg.xray_bin, cfg.socks_port,
        cfg.proxy_iface, cfg.policy, cfg.sni_capture ? "yes" : "no", cfg.probe_url,
        cfg.fragment ? "yes" : "no", cfg.fingerprint);

    fclose(f);
    return 0;
}
