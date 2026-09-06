#include "config.h"
#include "engine.h"
#include "rci.h"
#include "watchlist.h"
#include "log.h"
#include "node.h"
#include "nodelist.h"
#include "xraycfg.h"
#include "shadowfox.h"
#include "signals.h"
#include "status.h"
#include "webui.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static void usage(FILE *out)
{
    fprintf(out,
        SHADOWFOX_DAEMON " " VERSION " — менеджер Xray и доменной маршрутизации для Keenetic\n"
        "\n"
        "Использование: " SHADOWFOX_DAEMON " [флаги]\n"
        "\n"
        "  -c, --config ФАЙЛ     путь к shadowfox.conf (по умолчанию " DEFAULT_CONF_FILE ")\n"
        "  -f, --foreground      не уходить в фон\n"
        "      --genconfig КАТ   записать shadowfox.conf со всеми значениями по умолчанию\n"
        "      --link ССЫЛКА     собрать config.json из vless:// и вывести его\n"
        "      --sub ФАЙЛ        то же из файла: подписка base64 или список ссылок\n"
        "      --socks-port N    порт локального SOCKS для --link (по умолчанию 2080)\n"
        "      --listen АДРЕС    адрес входа SOCKS (по умолчанию 127.0.0.1)\n"
        "  -s, --status          показать состояние демона и выйти\n"
        "      --dry-run         показать план правил и выйти, ничего не меняя\n"
        "      --setup-proxy     напечатать команды для своего прокси в Keenetic\n"
        "      --setup-web       напечатать команды для доступа по доменному имени\n"
        "      --fragment        включить фрагментацию TLS и шум UDP\n"
        "      --no-fragment     выключить их явно (и так выключены)\n"
        "      --log УРОВЕНЬ     off | error | warn | info | debug\n"
        "      --КЛЮЧ ЗНАЧЕНИЕ   любой параметр из shadowfox.conf\n"
        "  -v, --version         версия\n"
        "  -h, --help            эта справка\n"
        "\n"
        "Сигналы:\n"
        "  SIGTERM, SIGINT       корректное завершение\n"
        "  SIGHUP                перечитать конфиг, переоткрыть журнал\n"
        "  SIGUSR1               восстановить правила (шлют ndm-хуки роутера)\n");
}

/* Уводит процесс в фон. Возвращает 0 в потомке, не возвращается в родителе. */
static int daemonize(void)
{
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid > 0) _exit(0);

    if (setsid() < 0) return -1;

    /* Второй fork: потомок гарантированно не станет лидером сессии
       и не сможет случайно захватить управляющий терминал. */
    pid = fork();
    if (pid < 0) return -1;
    if (pid > 0) _exit(0);

    umask(022);
    if (chdir("/") != 0) return -1;

    int null = open("/dev/null", O_RDWR);
    if (null >= 0) {
        dup2(null, STDIN_FILENO);
        dup2(null, STDOUT_FILENO);
        if (null > STDERR_FILENO) close(null);
    }
    return 0;
}

int main(int argc, char **argv)
{
    config_t cfg;
    config_defaults(&cfg);

    /* Первый проход: только --config и --genconfig, чтобы знать,
       какой файл читать, до разбора остальных флагов. */
    const char *conf_path = cfg.conf_file;

    for (int i = 1; i < argc; i++) {
        if ((!strcmp(argv[i], "-c") || !strcmp(argv[i], "--config")) && i + 1 < argc) {
            conf_path = argv[++i];
        } else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            usage(stdout);
            return 0;
        } else if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--version")) {
            printf(SHADOWFOX_DAEMON " " VERSION "\n");
            return 0;
        } else if (!strcmp(argv[i], "--link")) {
            if (i + 1 >= argc) {
                fprintf(stderr, "--link требует ссылку\n");
                return 2;
            }
            const char *link = argv[++i];

            xraycfg_opts_t opts;
            xraycfg_defaults(&opts);

            for (int k = 1; k < argc; k++) {
                if (!strcmp(argv[k], "--fragment")) {
                    opts.fragment = 1;
                    opts.noise    = 1;
                } else if (!strcmp(argv[k], "--no-fragment")) {
                    opts.fragment = 0;
                    opts.noise    = 0;
                } else if (!strcmp(argv[k], "--socks-port") && k + 1 < argc) {
                    opts.socks_port = atoi(argv[++k]);
                } else if (!strcmp(argv[k], "--listen") && k + 1 < argc) {
                    opts.listen = argv[++k];
                }
            }

            node_t node;
            char   err[128] = "";
            if (node_from_link(link, &node, err, sizeof(err)) != 0) {
                fprintf(stderr, "не разобрать ссылку: %s\n", err);
                return 1;
            }

            static char out[32768];
            if (xraycfg_build(&node, &opts, out, sizeof(out)) != 0) {
                fprintf(stderr, "не удалось собрать конфиг\n");
                return 1;
            }

            printf("%s\n", out);
            return 0;
        } else if (!strcmp(argv[i], "--sub")) {
            if (i + 1 >= argc) {
                fprintf(stderr, "--sub требует путь к файлу\n");
                return 2;
            }
            const char *path = argv[++i];

            FILE *f = fopen(path, "r");
            if (!f) {
                fprintf(stderr, "не открыть %s: %s\n", path, strerror(errno));
                return 1;
            }

            static char body[256 * 1024];
            size_t got = fread(body, 1, sizeof(body) - 1, f);
            int    truncated = !feof(f);
            fclose(f);
            body[got] = '\0';

            if (truncated) {
                fprintf(stderr, "файл %s больше %zu байт\n",
                        path, sizeof(body) - 1);
                return 1;
            }

            nodelist_t list;
            nodelist_init(&list);
            int added = nodelist_from_subscription(&list, body);
            if (added <= 0) {
                fprintf(stderr, "в %s не нашлось ни одной понятной ссылки\n", path);
                return 1;
            }
            if (list.skipped)
                fprintf(stderr, "пропущено неразобранных строк: %d\n", list.skipped);

            xraycfg_opts_t opts;
            xraycfg_defaults(&opts);
            for (int k = 1; k < argc; k++) {
                if (!strcmp(argv[k], "--fragment")) {
                    opts.fragment = 1;
                    opts.noise    = 1;
                } else if (!strcmp(argv[k], "--no-fragment")) {
                    opts.fragment = 0;
                    opts.noise    = 0;
                } else if (!strcmp(argv[k], "--socks-port") && k + 1 < argc) {
                    opts.socks_port = atoi(argv[++k]);
                } else if (!strcmp(argv[k], "--listen") && k + 1 < argc) {
                    opts.listen = argv[++k];
                }
            }

            static char out[262144];
            if (xraycfg_build_list(&list, &opts, out, sizeof(out)) != 0) {
                fprintf(stderr, "не удалось собрать конфиг\n");
                return 1;
            }

            fprintf(stderr, "узлов: %d\n", list.count);
            printf("%s\n", out);
            return 0;
        } else if (!strcmp(argv[i], "-s") || !strcmp(argv[i], "--status")) {
            config_t st;
            config_defaults(&st);
            str_copy(st.conf_file, sizeof(st.conf_file), conf_path);
            config_load_file(&st, st.conf_file);
            config_apply_args(&st, argc, argv);
            return status_print(&st);
        } else if (!strcmp(argv[i], "--setup-web")) {
            config_t sw;
            config_defaults(&sw);
            str_copy(sw.conf_file, sizeof(sw.conf_file), conf_path);
            config_load_file(&sw, sw.conf_file);
            config_apply_args(&sw, argc, argv);

            char lan[64] = "";
            if (sw.web_bind[0])
                str_copy(lan, sizeof(lan), sw.web_bind);
            else if (!iface_ipv4(sw.capture_iface, lan, sizeof(lan))) {
                fprintf(stderr, "не узнать адрес на %s\n", sw.capture_iface);
                return 1;
            }

            printf("# Публикация веб-интерфейса на поддомене твоего\n"
                   "# доменного имени Keenetic. Роутер сам сделает HTTPS и\n"
                   "# спросит логин с паролем — своей проверки входа у нас\n"
                   "# нет и не нужно.\n\n");

            printf("ndmc -c \"ip http proxy %s\"\n", sw.web_proxy);
            printf("ndmc -c \"ip http proxy %s upstream http %s %d\"\n",
                   sw.web_proxy, lan, sw.web_port);
            printf("ndmc -c \"ip http proxy %s domain ndns\"\n", sw.web_proxy);
            printf("ndmc -c \"ip http proxy %s ssl redirect\"\n", sw.web_proxy);
            printf("ndmc -c \"ip http proxy %s security-level public\"\n", sw.web_proxy);
            printf("ndmc -c \"ip http proxy %s auth\"\n", sw.web_proxy);
            printf("ndmc -c \"system configuration save\"\n");

            printf("\n# После этого интерфейс откроется по адресу\n"
                   "#   https://%s.<твоё доменное имя>\n", sw.web_proxy);
            printf("# и из дома, и из интернета — с паролем от роутера.\n");
            return 0;
        } else if (!strcmp(argv[i], "--setup-proxy")) {
            config_t sp;
            config_defaults(&sp);
            str_copy(sp.conf_file, sizeof(sp.conf_file), conf_path);
            config_load_file(&sp, sp.conf_file);
            config_apply_args(&sp, argc, argv);

            /* Прокси-клиент Keenetic ходит на LAN-адрес роутера, а не на
               петлю — это видно в рабочей настройке. Поэтому адрес берём
               с интерфейса, а не подставляем 127.0.0.1. */
            char lan[64] = "";
            if (!iface_ipv4(sp.capture_iface, lan, sizeof(lan))) {
                fprintf(stderr,
                        "не удалось узнать адрес на %s. Укажи интерфейс "
                        "локальной сети параметром interface\n",
                        sp.capture_iface);
                return 1;
            }

            printf("# Команды выполняются на роутере. Посмотри их глазами:\n"
                   "# они меняют настройки устройства, а не наши файлы.\n\n");

            printf("ndmc -c \"interface %s\"\n", sp.proxy_iface);
            printf("ndmc -c \"interface %s description Shadow-Fox\"\n", sp.proxy_iface);
            printf("ndmc -c \"interface %s security-level public\"\n", sp.proxy_iface);
            printf("ndmc -c \"interface %s ip global 1\"\n", sp.proxy_iface);
            printf("ndmc -c \"interface %s proxy protocol socks5\"\n", sp.proxy_iface);
            printf("ndmc -c \"interface %s proxy upstream %s %d\"\n",
                   sp.proxy_iface, lan, sp.socks_port);
            printf("ndmc -c \"interface %s proxy socks5-udp\"\n", sp.proxy_iface);
            printf("ndmc -c \"interface %s up\"\n", sp.proxy_iface);
            printf("ndmc -c \"system configuration save\"\n");

            printf("\n# Затем в панели роутера:\n"
                   "#   Приоритеты подключений -> Политики доступа -> %s\n"
                   "#   отметить подключение Shadow-Fox и снять остальные.\n",
                   sp.policy);
            printf("# Без этого шага политика получит метку, но заворачивать\n"
                   "# трафик будет некуда.\n");
            return 0;
        } else if (!strcmp(argv[i], "--dry-run")) {
            config_t dry;
            config_defaults(&dry);
            str_copy(dry.conf_file, sizeof(dry.conf_file), conf_path);
            config_load_file(&dry, dry.conf_file);
            config_apply_args(&dry, argc, argv);

            static engine_t preview;
            engine_init(&preview);
            rt_find_bins(&preview.rt);
            ips_find_bin(preview.ips.bin, sizeof(preview.ips.bin));
            preview.rt.ipv6 = dry.ipv6 && preview.rt.ip6tables[0];

            char dpath[CFG_PATH_MAX + 32], ipath[CFG_PATH_MAX + 32];
            snprintf(dpath, sizeof(dpath), "%s/domain.conf", dry.conf_dir);
            snprintf(ipath, sizeof(ipath), "%s/ip.list", dry.conf_dir);
            wl_load_domains(&preview.wl, dpath);
            wl_load_cidrs(&preview.wl, ipath);
            wl_classify_targets(&preview.wl, NULL);

            /* Метки спрашиваем и здесь: без них план для целей-политик
               выглядел бы пустым, и было бы непонятно почему. */
            for (int k = 0; k < preview.wl.group_count; k++) {
                wl_group_t *g = &preview.wl.groups[k];
                if (g->target != WL_TARGET_POLICY) continue;
                unsigned mk = 0;
                if (rci_policy_mark(&preview.rci, g->iface, &mk) == 0)
                    g->policy_mark = mk;
            }

            fprintf(stderr, "групп %d, доменов %d, подсетей %d, "
                            "пропущено строк %d\n",
                    preview.wl.group_count, preview.wl.domain_count,
                    preview.wl.cidr_count, preview.wl.skipped);

            engine_print_plan(&preview);
            return 0;
        } else if (!strcmp(argv[i], "--genconfig")) {
            const char *dir = (i + 1 < argc) ? argv[++i] : DEFAULT_CONF_DIR;
            char path[CFG_PATH_MAX];
            snprintf(path, sizeof(path), "%s/shadowfox.conf", dir);
            if (config_write_default(path) != 0) {
                fprintf(stderr, "не удалось записать %s: %s\n", path, strerror(errno));
                return 1;
            }
            printf("записан %s\n", path);
            return 0;
        }
    }

    str_copy(cfg.conf_file, sizeof(cfg.conf_file), conf_path);

    if (config_load_file(&cfg, cfg.conf_file) != 0) {
        fprintf(stderr, "ошибки в %s, продолжаю на значениях по умолчанию\n",
                cfg.conf_file);
    }

    /* Второй проход: флаги CLI перекрывают файл. */
    if (config_apply_args(&cfg, argc, argv) != 0) {
        usage(stderr);
        return 2;
    }

    int running = pidfile_read_alive(cfg.pid_file);
    if (running) {
        fprintf(stderr, SHADOWFOX_DAEMON " уже запущен (pid %d)\n", running);
        return 1;
    }

    if (!cfg.foreground && daemonize() != 0) {
        fprintf(stderr, "не удалось уйти в фон: %s\n", strerror(errno));
        return 1;
    }

    log_open(cfg.foreground ? NULL : cfg.log_file, cfg.log_level);
    signals_install();

    if (pidfile_write(cfg.pid_file) != 0)
        log_warn("не удалось записать pid-файл %s: %s",
                 cfg.pid_file, strerror(errno));

    log_info(SHADOWFOX_DAEMON " " VERSION " запущен, pid %ld, конфиг %s",
             (long)getpid(), cfg.conf_file);

    static engine_t engine;
    engine_init(&engine);

    static http_t web;
    http_init(&web);

    char eerr[256] = "";
    if (cfg.auto_start) {
        if (engine_start(&engine, &cfg, eerr, sizeof(eerr)) != 0)
            log_error("маршрутизация не поднята: %s", eerr);
    } else {
        log_info("autoStart выключен, правила не ставятся");
    }

    if (cfg.web_enabled) {
        char werr[192] = "";
        if (webui_open(&web, &cfg, werr, sizeof(werr)) == 0)
            log_info("веб-интерфейс: http://%s:%d%s", web.bind_addr, web.port,
                     cfg.web_token[0] ? " (нужен токен)" : "");
        else
            log_warn("веб-интерфейс не поднят: %s", werr);
    }

    while (!g_shutdown) {
        if (g_reload) {
            g_reload = 0;
            log_info("SIGHUP: перечитываю конфиг");

            config_t fresh;
            config_defaults(&fresh);
            str_copy(fresh.conf_file, sizeof(fresh.conf_file), cfg.conf_file);

            /* Тот же порядок, что при старте: файл, затем флаги CLI поверх.
               Без второго шага перечитывание молча теряет всё, что задано
               в командной строке, — включая путь к pid-файлу. */
            if (config_load_file(&fresh, fresh.conf_file) == 0 &&
                config_apply_args(&fresh, argc, argv) == 0) {
                cfg = fresh;
                log_open(cfg.foreground ? NULL : cfg.log_file, cfg.log_level);
                if (engine_reload(&engine, &cfg, eerr, sizeof(eerr)) != 0)
                    log_error("правила не переставлены: %s", eerr);
                else
                    log_info("конфиг перечитан");

                /* Адрес, порт или токен могли смениться. */
                http_close(&web);
                if (cfg.web_enabled) {
                    char werr[192] = "";
                    if (webui_open(&web, &cfg, werr, sizeof(werr)) != 0)
                        log_warn("веб-интерфейс не поднят: %s", werr);
                }
            } else {
                log_error("конфиг с ошибками, оставляю прежний");
            }
        }

        if (g_restore) {
            g_restore = 0;
            /* Роутер переписал netfilter или сменил состояние интерфейса.
               План идемпотентен, поэтому просто применяем его заново. */
            /* Не применяем сразу: наши же правки netfilter поднимут
               хуки роутера, и те пришлют ещё сигналов. Откладываем и
               схлопываем всплеск в одно применение. */
            engine_request_restore(&engine, time(NULL));
        }

        /* Ждём либо пакет, либо секунду: накопленные адреса надо отдавать
           в ipset регулярно, даже когда в сети тихо. Сигнал прерывает
           ожидание, и мы обработаем его на следующем витке. */
        int            fd  = engine_fd(&engine);
        int            wfd = http_fd(&web);
        int            max = fd > wfd ? fd : wfd;
        struct timeval tv  = { 1, 0 };
        fd_set         rd;

        FD_ZERO(&rd);
        if (fd  >= 0) FD_SET(fd,  &rd);
        if (wfd >= 0) FD_SET(wfd, &rd);
        select(max >= 0 ? max + 1 : 0, max >= 0 ? &rd : NULL, NULL, NULL, &tv);

        if (wfd >= 0) webui_poll(&web, &engine, &cfg);
        engine_tick(&engine, time(NULL));
    }

    log_info("завершение по сигналу, снимаю правила");
    http_close(&web);
    engine_stop(&engine);

    log_info("поймано адресов %lu, пачек в ipset %lu, восстановлений %lu",
             engine.matched, engine.flushes, engine.restores);

    pidfile_remove(cfg.pid_file);
    log_close();
    return 0;
}
