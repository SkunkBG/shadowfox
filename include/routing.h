#ifndef SHADOWFOX_ROUTING_H
#define SHADOWFOX_ROUTING_H

#include "watchlist.h"

/* Правила маршрутизации: метка по совпадению в наборе, ip rule по метке,
   маршрут по умолчанию в таблице группы.

   Команды сначала складываются в план, и только потом выполняются. Так
   их видно тестами: на macOS ни iptables, ни ip нет, а ошибиться в
   аргументах — самое лёгкое дело. */

/* На группу с целью-интерфейсом уходит пять команд на семью адресов,
   плюс восемь на цепочку и переходы. Раньше стояло 128 — и план на
   тринадцать групп с IPv6 не помещался, а не поместившийся план
   отвергается целиком: ни одна группа не маршрутизировалась. */
#define RT_CMDS_MAX (16 + 10 * WL_GROUPS_MAX)
/* Самое длинное правило — установка метки политики: две проверки метки,
   совпадение в наборе и CONNMARK, всего 23 аргумента. Запас небольшой,
   но переполнение не молчит: план помечается негодным и не выполняется. */
#define RT_ARGS_MAX  28
#define RT_ARG_LEN   48
#define RT_BIN_MAX   128

/* Прежняя своя цепочка в mangle. Правила теперь стоят прямо в
   PREROUTING, как у HydraRoute; имя нужно только чтобы снять цепочку
   у тех, кто обновился. */
#define RT_CHAIN     "SHADOWFOX"
#define RT_GUARD     "SHADOWFOX_IN"   /* закрывает порт ядра от сети */

typedef struct {
    char argv[RT_ARGS_MAX][RT_ARG_LEN];
    int  argc;
    int  may_fail;   /* удаление несуществующего правила — не ошибка */
    /* «Поставить, если нет»: argv — форма проверки с -C; если она не
       проходит, команда выполняется с -A (1) либо -I <цепочка> 1 (2).
       Так врезка в чужую цепочку не плодит дублей и не снимается
       перед вставкой — а снятие было зазором без метки. */
    int  ensure;
} rt_cmd_t;

/* Текст для iptables-restore --noflush: своя цепочка объявляется и
   наполняется одной атомарной операцией. Раньше цепочка чистилась и
   наполнялась десятками отдельных вызовов iptables; секунду-две она
   стояла пустой, все туннельные соединения теряли метку, уходили
   напрямую и обрывались — и клиенты разом переустанавливали их через
   сервер. У HydraRoute ровно поэтому правила ставятся так. */
#define RT_BATCH_BYTES (4096 + 512 * WL_GROUPS_MAX)

typedef struct {
    rt_cmd_t cmds[RT_CMDS_MAX];
    int      count;
    int      overflow;
    char     batch4[RT_BATCH_BYTES];   /* для iptables-restore (защита порта), пусто — нет */
    char     batch6[RT_BATCH_BYTES];   /* не используется, оставлено для формы */
} rt_plan_t;

typedef struct {
    char iptables[RT_BIN_MAX];
    char ip6tables[RT_BIN_MAX];
    char iptables_restore[RT_BIN_MAX];    /* пусто — атомарной подмены нет */
    char ip6tables_restore[RT_BIN_MAX];
    char ip[RT_BIN_MAX];
    int  ipv6;       /* обслуживать ли IPv6 */
    int  v6_reject;  /* цель REJECT есть в ip6tables; иначе DROP */
    int  timeout;
    int  guard_port; /* порт SOCKS ядра, который закрываем от сети; 0 — нет */
} rt_t;

void rt_init(rt_t *r);
int  rt_find_bins(rt_t *r);   /* 1, если нашлись iptables и ip */
/* Есть ли в ip6tables цель REJECT: без модуля остаётся DROP, а с ним
   устройство получает отказ сразу и уходит на IPv4 без ожидания. */
void rt_probe_v6_reject(rt_t *r);

/* Строят план установки и снятия правил. */
void rt_plan_apply(rt_plan_t *p, const rt_t *r, const wl_t *w);
void rt_plan_remove(rt_plan_t *p, const rt_t *r, const wl_t *w);

/* Выполняет план. Возвращает 0, если ни одна обязательная команда не
   провалилась. */
int  rt_run(const rt_plan_t *p, const rt_t *r, char *err, unsigned err_size);

/* Счётчики пакетов из вывода `iptables -L -v -x`.

   Вынесено отдельной чистой функцией, потому что разбор здесь дважды
   ошибался молча. Строки классифицируются по имени действия, а не по
   точной подстроке: iptables печатает «CONNMARK set» для политики,
   но «MARK xset» — для группы, заворачивающей на интерфейс. Проверка
   на «MARK set» второе не ловила, и трафик таких групп не считался
   вовсе, сколько бы его ни шло.

   Складываем, а не берём последнее совпадение: правил в цепочке
   столько же, сколько групп. */
void rt_parse_counters(const char *text, const wl_t *w, unsigned long *marked,
                       unsigned long *restored);

/* То же, но опросив ядро по обеим семьям адресов: `-L PREROUTING`, из
   него только строки с нашими наборами. Возвращает 0, если удалось. */
int  rt_counters(const rt_t *r, const wl_t *w, unsigned long *marked, unsigned long *restored);

/* Устаревшие правила в дампе `-S PREROUTING`: наши по набору, но не
   совпадающие с тем, что должно стоять (сменилась метка политики,
   цель, группа выключена). cb вызывается на каждое, без «-A PREROUTING».
   Чистая функция — для тестов. Возвращает число найденных. */
int  rt_stale_rules(const char *dump, const wl_t *w, int v6,
                    void (*cb)(const char *rule, void *ctx), void *ctx);

/* То же с живого ядра, с удалением. Возвращает число снятых. */
int  rt_prune_stale(const rt_t *r, const wl_t *w);

/* Печатает команду одной строкой — для тестов и журнала. */
const char *rt_cmd_text(const rt_cmd_t *c, char *dst, unsigned size);

#endif /* SHADOWFOX_ROUTING_H */
