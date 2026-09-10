#ifndef SHADOWFOX_XRAYCFG_H
#define SHADOWFOX_XRAYCFG_H

#include "node.h"
#include "nodelist.h"
#include "xjson.h"

#include <stddef.h>

typedef struct {
    const char *listen;   /* адрес входа; см. комментарий в xraycfg.c */
    int  socks_port;      /* локальный вход, к которому цепляется Proxy0 */
    int  fragment;        /* резать TLS ClientHello — только для tls, не reality */
    const char *fingerprint;  /* перекрыть отпечаток uTLS, "" — из ссылки */
    int  sniffing;        /* определять домен для маршрутизации */
    const char *socks_user;   /* пароль на вход: пусто — без него */
    const char *socks_pass;
    const char *log_level;
    const char *error_log;      /* куда ядру писать ошибки; NULL — никуда */
    const char *probe_url;      /* чем балансировщик меряет задержку */
    const char *probe_interval;
} xraycfg_opts_t;

void xraycfg_defaults(xraycfg_opts_t *o);

/* Собирает config.json для одного узла. */
int  xraycfg_build(const node_t *n, const xraycfg_opts_t *o,
                   char *buf, size_t size);

/* Собирает config.json для списка узлов. При двух и более узлах
   добавляет балансировщик по наименьшей задержке.
   Возвращает 0 при успехе, -1 если список пуст или не хватило буфера. */
/* Конфиг из подписки Xray JSON: outbounds, routing, наблюдатель и
   прочее берутся из конфига панели как есть, входы и журнал — свои,
   dns панели отбрасывается (иначе имена серверов уходили бы открытым
   UDP мимо DoT роутера), правила с geoip/geosite — тоже: файлов
   geo на роутере нет, и ядро с ними не стартует. */
int  xraycfg_build_from_json(const xjson_item_t *it, const xraycfg_opts_t *o,
                             char *buf, size_t size);

int  xraycfg_build_list(const nodelist_t *l, const xraycfg_opts_t *o,
                        char *buf, size_t size);

#endif /* SHADOWFOX_XRAYCFG_H */
