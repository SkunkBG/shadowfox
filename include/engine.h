#ifndef SHADOWFOX_ENGINE_H
#define SHADOWFOX_ENGINE_H

#include "config.h"
#include "dnscap.h"
#include "ipsets.h"
#include "rci.h"
#include "supervise.h"
#include "routing.h"
#include "watchlist.h"

#include <time.h>

/* Связывает всё вместе: списки, наборы, правила, перехват. */

typedef struct engine {
    wl_t   wl;
    ips_t  ips;
    rt_t   rt;
    dcap_t cap;
    rci_t  rci;
    sv_t   xray;           /* свой экземпляр ядра */
    int    xray_managed;   /* мы его подняли и следим за ним */

    int    rules_applied;
    int    capturing;
    time_t started_at;
    time_t last_flush;
    time_t last_stats;
    time_t last_stats_log;
    const config_t *cfg;   /* для выкладывания состояния */
    time_t restore_due;   /* когда применить накопленный запрос */

    unsigned long matched;   /* адресов, попавших под правила */
    unsigned long flushes;
    unsigned long restores;
    unsigned long marked_conns;
    int           policies_pending;   /* политик без метки */
    int           may_create_policy;
    int           ipset_timeout;
} engine_t;

void engine_init(engine_t *e);

/* Читает списки, ставит правила, открывает перехват.
   Отсутствие перехвата не смертельно: подсети из ip.list продолжают
   работать, и об этом будет сказано в журнал. */
int  engine_start(engine_t *e, const config_t *cfg, char *err, unsigned err_size);

/* Снимает правила и закрывает перехват. */
void engine_stop(engine_t *e);

/* Перечитывает списки и переставляет правила. */
int  engine_reload(engine_t *e, const config_t *cfg, char *err, unsigned err_size);

/* Включает и выключает своё ядро по просьбе из интерфейса. Выбор
   запоминается файлом в каталоге настроек: иначе перезапуск демона
   молча поднял бы то, что выключили руками.
   Возвращает 0 при успехе. */
int  engine_core_set(engine_t *e, const config_t *cfg, int on,
                     char *err, unsigned err_size);

/* Выключено ли ядро волей пользователя. */
int  engine_core_off(const config_t *cfg);

/* Восстанавливает правила после того, как роутер переписал netfilter.
   Вызывается по SIGUSR1 из ndm-хуков. */
int  engine_restore(engine_t *e, char *err, unsigned err_size);

/* Откладывает восстановление на пару секунд. Правка netfilter сама
   поднимает хуки роутера, и те присылают новый SIGUSR1 — без задержки
   получилась бы цепная реакция. */
void engine_request_restore(engine_t *e, time_t now);

/* Один проход главного цикла: забрать пойманное, отдать накопленное. */
void engine_tick(engine_t *e, time_t now);

/* Дескриптор перехвата для ожидания в главном цикле, либо -1. */
int  engine_fd(const engine_t *e);

/* Печатает план правил, ничего не применяя. */
void engine_print_plan(const engine_t *e);

#endif /* SHADOWFOX_ENGINE_H */
