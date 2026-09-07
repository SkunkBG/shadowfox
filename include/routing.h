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

/* Своя цепочка: чистить и наполнять можно свободно, не задевая чужие
   правила в PREROUTING. */
#define RT_CHAIN     "SHADOWFOX"
#define RT_GUARD     "SHADOWFOX_IN"   /* закрывает порт ядра от сети */

typedef struct {
    char argv[RT_ARGS_MAX][RT_ARG_LEN];
    int  argc;
    int  may_fail;   /* удаление несуществующего правила — не ошибка */
} rt_cmd_t;

typedef struct {
    rt_cmd_t cmds[RT_CMDS_MAX];
    int      count;
    int      overflow;
} rt_plan_t;

typedef struct {
    char iptables[RT_BIN_MAX];
    char ip6tables[RT_BIN_MAX];
    char ip[RT_BIN_MAX];
    int  ipv6;       /* обслуживать ли IPv6 */
    int  timeout;
    int  guard_port; /* порт SOCKS ядра, который закрываем от сети; 0 — нет */
} rt_t;

void rt_init(rt_t *r);
int  rt_find_bins(rt_t *r);   /* 1, если нашлись iptables и ip */

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
void rt_parse_counters(const char *text, unsigned long *marked,
                       unsigned long *restored);

/* То же, но опросив ядро по обеим семьям адресов. Возвращает 0, если
   цепочка нашлась хотя бы в одной. */
int  rt_counters(const rt_t *r, unsigned long *marked, unsigned long *restored);

/* Печатает команду одной строкой — для тестов и журнала. */
const char *rt_cmd_text(const rt_cmd_t *c, char *dst, unsigned size);

#endif /* SHADOWFOX_ROUTING_H */
