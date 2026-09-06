#include "config.h"
#include "log.h"
#include "node.h"
#include "nodelist.h"
#include "xraycfg.h"
#include "shadowfox.h"
#include "signals.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
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

    /* Главный цикл. На этапе 1 демон только держится живым и корректно
       отвечает на сигналы — это проверяемый каркас для этапов 3 и 4. */
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
                log_info("конфиг перечитан");
            } else {
                log_error("конфиг с ошибками, оставляю прежний");
            }
        }

        if (g_restore) {
            g_restore = 0;
            /* Роутер переписал netfilter или сменил состояние интерфейса.
               Этап 4 повесит сюда восстановление правил. */
            log_info("SIGUSR1: запрошено восстановление правил");
        }

        pause();                        /* просыпаемся только по сигналу */
    }

    log_info("завершение по сигналу");
    pidfile_remove(cfg.pid_file);
    log_close();
    return 0;
}
