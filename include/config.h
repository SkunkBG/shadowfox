#ifndef SHADOWFOX_CONFIG_H
#define SHADOWFOX_CONFIG_H

#include "log.h"

#define CFG_PATH_MAX 256
#define WL_NAME_MAX_CFG 64

typedef struct {
    char        conf_file[CFG_PATH_MAX];
    char        conf_dir[CFG_PATH_MAX];      /* где лежат domain.conf и ip.list */
    char        capture_iface[32];           /* где слушать DNS */
    char        pid_file[CFG_PATH_MAX];
    char        log_file[CFG_PATH_MAX];
    log_level_t log_level;
    int         foreground;      /* 1 — не уходить в фон */
    int         auto_start;      /* ставить правила сразу при старте */
    int         ipv6;            /* обслуживать ли IPv6 */
    int         create_policy;   /* можно ли заводить политики на роутере */
    int         ipset_timeout;   /* секунд жизни записи в наборе, 0 — вечно */
    int         sni_capture;     /* читать имена из TLS ClientHello */

    /* Устойчивость к DPI. Ровно те ручки, отсутствие которых, судя по
       всему, и хоронило neofit со временем. */
    int         fragment;        /* резать TLS ClientHello (только tls) */
    char        fingerprint[16]; /* перекрыть отпечаток uTLS, пусто — из ссылки */

    /* Свой экземпляр Xray и своё прокси-подключение в Keenetic. */
    char        policy[WL_NAME_MAX_CFG];      /* политика для своего прокси */
    char        proxy_iface[32];              /* Proxy1 и т.п. */
    int         socks_port;                   /* порт своего socks */
    char        socks_secret[CFG_PATH_MAX];   /* файл с паролем SOCKS, пусто — без пароля */
    char        nodes_file[CFG_PATH_MAX];     /* ссылки или подписка */
    char        xray_config[CFG_PATH_MAX];    /* куда писать конфиг */
    char        xray_bin[CFG_PATH_MAX];       /* пусто — искать самим */

    /* Веб-интерфейс. */
    int         web_enabled;
    int         web_port;
    char        web_bind[64];                 /* пусто — адрес интерфейса ЛС */
    char        web_token[64];                /* пусто — без проверки */
    char        router_host[64];              /* пусто — адрес на интерфейсе */
    int         router_port;                  /* веб-сервер роутера: вход */
    char        web_proxy[32];                /* имя в прокси роутера */
} config_t;

/* Заполняет cfg встроенными значениями по умолчанию. */
void config_defaults(config_t *cfg);

/* Читает key=value из файла. Отсутствие файла — не ошибка, вернёт 0.
   Возвращает -1 только при ошибке чтения или разбора. */
int  config_load_file(config_t *cfg, const char *path);

/* Пишет полный конфиг со всеми ключами и дефолтами. Для --genconfig. */
int  config_write_default(const char *path);

/* Применяет одну пару ключ/значение. Возвращает 0, если ключ известен. */
int  config_set(config_t *cfg, const char *key, const char *value);

/* Накладывает флаги CLI поверх уже загруженного конфига.
   Вызывается и при старте, и после каждого SIGHUP — иначе перечитывание
   файла молча затирает то, что задано в командной строке.
   Возвращает 0, либо -1 при неизвестном флаге (сообщение в stderr). */
int  config_apply_args(config_t *cfg, int argc, char **argv);

#endif /* SHADOWFOX_CONFIG_H */
