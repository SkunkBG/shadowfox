#ifndef SHADOWFOX_XRAYCFG_H
#define SHADOWFOX_XRAYCFG_H

#include "node.h"
#include "nodelist.h"

#include <stddef.h>

typedef struct {
    const char *listen;   /* адрес входа; см. комментарий в xraycfg.c */
    int  socks_port;      /* локальный вход, к которому цепляется Proxy0 */
    int  fragment;        /* резать TLS ClientHello */
    int  noise;           /* добавлять шум в UDP */
    int  sniffing;        /* определять домен для маршрутизации */
    const char *log_level;
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
int  xraycfg_build_list(const nodelist_t *l, const xraycfg_opts_t *o,
                        char *buf, size_t size);

#endif /* SHADOWFOX_XRAYCFG_H */
