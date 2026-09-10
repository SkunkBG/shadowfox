#ifndef SHADOWFOX_ENGINE_H
#define SHADOWFOX_ENGINE_H

#include "config.h"
#include "dnscap.h"
#include "nodelist.h"
#include "subs.h"
#include "ipsets.h"
#include "tcpstat.h"
#include "sockrtt.h"
#include "rci.h"
#include "snicap.h"
#include "supervise.h"
#include "routing.h"
#include "watchlist.h"

#include <time.h>

/* Связывает всё вместе: списки, наборы, правила, перехват. */

/* Адресов в памяти о разложенном. Один TikTok за сутки даёт восемьсот,
   YouTube пятьсот, а срок жизни в наборах — сутки. При переполнении
   вытесненный адрес, который всё ещё в наборе, выглядит новым, и
   демон рвёт соединение, которое шло верно, — на 1024 это начиналось
   через час работы. 8192 записи по 24 байта — под 200 КБ, роутер
   выдержит. */
#define ENG_KNOWN_MAX 8192
#define ENG_PENDING_MAX 64

/* Подписку перечитываем раз в шесть часов: список серверов у панели
   меняется редко, а каждая загрузка — соединение с панелью, которое
   провайдер видит. После неудачи пробуем чаще. */
#define ENGINE_SUBS_REFRESH (6 * 3600)
#define ENGINE_SUBS_RETRY   (10 * 60)

typedef struct engine {
    wl_t   wl;
    ips_t  ips;
    rt_t   rt;
    dcap_t cap;
    scap_t sni;
    rci_t  rci;
    sv_t   xray;           /* свой экземпляр ядра */
    int    xray_managed;   /* мы его подняли и следим за ним */
    char   xray_version[32];   /* спрошенная у бинарника, пусто — не знаем */
    time_t xray_ver_try;       /* когда пробовали спросить */
    char   xray_listen[64];    /* где слушает наш SOCKS */

    /* Живой ли туннель — пассивно, по TCP-сокетам самого ядра к
       серверу. Активная проверка по расписанию была сердцебиением, по
       которому провайдер распознавал туннель, и снята; см. tcpstat.h. */
    int     node_ports[TCPSTAT_PORTS_MAX];
    int     node_port_count;
    time_t  tunnel_sampled;    /* когда смотрели сокеты последний раз */
    int     tunnel_state;      /* 0 — нет данных, 1 — соединения есть, -1 — сервер не отвечает */
    time_t  tunnel_since;      /* с какого момента в этом состоянии */
    int     tunnel_established;
    int     tunnel_pending;    /* SYN без ответа */
    unsigned long tunnel_retrans;      /* повторов на установленных, последний срез */
    unsigned long tunnel_retrans_prev;
    int     tunnel_retrans_grow;       /* повторы растут между срезами */
    char    tunnel_why[160];
    int     tunnel_rtt_ms;     /* RTT до сервера по живым соединениям ядра, -1 — нет данных */

    /* Подписка и выбор сервера. Из списка ядру отдаётся один сервер:
       балансировщик со своим наблюдателем каждые пять минут ходил бы
       через каждый сервер к gstatic — то самое сердцебиение, которое
       мы убрали. Включается явно, balancer=yes. */
    int    subs_urls;          /* адресов подписок в файле ссылок */
    int    subs_ok;            /* последняя загрузка удалась */
    int    subs_cached;        /* список взят из кеша */
    time_t subs_at;            /* когда загружали */
    char   subs_host[SUBS_HOST_MAX];
    char   subs_error[160];
    int    server_count;       /* серверов в списке до выбора */
    char   server_tags[NODELIST_MAX][NODE_TAG_MAX];
    char   server_active[NODE_TAG_MAX];
    char   server_filter[64];  /* метка в имени: остальные серверы отбрасываются */
    int    subs_force;         /* страница попросила перекачать подписку */
    char   dev_model[96];      /* модель и прошивка для заголовков подписки */
    char   dev_osver[48];
    int    dev_asked;          /* у роутера уже спрашивали */
    time_t nodes_mtime;        /* файл ссылок менялся — качать заново */

    int    rules_applied;
    int    capturing;
    int    sniffing;
    time_t started_at;
    time_t last_flush;
    time_t last_stats;
    time_t last_stats_log;
    const config_t *cfg;   /* для выкладывания состояния */
    time_t restore_due;   /* когда применить накопленный запрос */

    unsigned long matched;   /* адресов, попавших под правила */
    unsigned long flushes;
    unsigned long restores;
    /* Счётчики правил из ядра. Опрашиваются раз в минуту вместе с
       выкладкой состояния: страница обновляется чаще, но ради неё
       порождать iptables каждые десять секунд ни к чему.

       Раньше marked_conns не заполнялся вообще и уходил в веб-интерфейс
       постоянным нулём — счётчик, который выглядит сигналом, а измеряет
       пустоту, хуже отсутствующего. */
    unsigned long marked_conns;
    unsigned long restored_pkts;
    long          addr4[WL_GROUPS_MAX];   /* записей в наборах, -1 — нет набора */
    long          addr6[WL_GROUPS_MAX];

    /* Перехват SNI. Считаем врозь имена, новые адреса и оборванные
       соединения: по одному числу не отличить «имён не видим» от
       «видим, но всё уже знаем», а лечатся они по-разному. */
    unsigned long sni_names;     /* имён под правилами */
    unsigned long sni_new;       /* из них дали новый адрес */
    unsigned long sni_broken;    /* соединений оборвано */
    unsigned long sni_throttled; /* обрывов не сделано: бюджет исчерпан */
    time_t        break_sec;     /* секунда, за которую считаем обрывы */
    int           break_in_sec;

    /* Обрывы, отложенные до конца прохода по пакетам. Раньше на каждый
       новый адрес внутри цикла чтения делались два порождения процесса
       — ipset restore и conntrack; одна вкладка с сорока доменами
       блокировала цикл на секунды. Теперь адреса копятся, набор
       сбрасывается один раз, и уже потом обрывы. */
    struct {
        unsigned char family;
        unsigned char src[16], dst[16];
        unsigned      sport, dport;
    } pending[ENG_PENDING_MAX];
    int           pending_count;
    int           pending_lost;   /* не поместилось — просто не оборвём */
    char          ct_bin[128];   /* путь к conntrack, пустой — не искали */
    int           ct_checked;
    int           ct_warned;

    /* Что уже разложено по наборам. Нужно ровно для перехвата SNI:
       ClientHello виден и у соединений, которые и так идут по туннелю,
       и без этой памяти мы обрывали бы каждое из них по кругу.

       Пополняется обоими путями, и через DNS тоже: иначе первое
       соединение к адресу, узнанному из DNS, обрывалось бы зря. */
    struct {
        unsigned char addr[16];
        unsigned char family;
        short         group;
        time_t        at;
    } known[ENG_KNOWN_MAX];
    int           known_count;
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

int  engine_restore(engine_t *e, char *err, unsigned err_size);

/* Откладывает восстановление на пару секунд. Правка netfilter сама
   поднимает хуки роутера, и те присылают новый SIGUSR1 — без задержки
   получилась бы цепная реакция. */
void engine_request_restore(engine_t *e, time_t now);

/* Один проход главного цикла: забрать пойманное, отдать накопленное. */
void engine_tick(engine_t *e, time_t now);
/* Со страницы: перекачать подписку при ближайшем перечитывании. */
void engine_refresh_subscription(engine_t *e);

/* Дескриптор перехвата для ожидания в главном цикле, либо -1. */
/* Дескрипторы, которые главный цикл обязан держать в select.

   Их два: перехват DNS и перехват SNI. Для SNI ожидание до следующего
   тика недопустимо — за эту секунду соединение успеет пройти мимо
   туннеля целиком. Возвращает, сколько записано. */
int  engine_fds(const engine_t *e, int *out, int max);

/* Печатает план правил, ничего не применяя. */
void engine_print_plan(const engine_t *e);

#endif /* SHADOWFOX_ENGINE_H */
