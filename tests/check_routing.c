/* Проверяет, какие именно команды iptables и ip мы формируем. На macOS
   их нет, но ошибка в аргументах — самое вероятное место, и увидеть её
   надо здесь, а не по последствиям на роутере. */
#include "routing.h"
#include "shadowfox.h"
#include "watchlist.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int failures = 0;

#define CHECK(cond, ...)                                     \
    do {                                                     \
        if (!(cond)) {                                       \
            printf("  ПРОВАЛ %s:%d: ", __FILE__, __LINE__);  \
            printf(__VA_ARGS__);                             \
            printf("\n");                                    \
            failures++;                                      \
        }                                                    \
    } while (0)

static char g_dir[96];

static void load_lists(wl_t *w)
{
    char path[160];
    snprintf(path, sizeof(path), "%s/d.conf", g_dir);

    FILE *f = fopen(path, "w");
    fputs("[youtube]\ninterface = Proxy0\ngooglevideo.com\n"
          "[soc]\ninterface = Proxy1\nexample.net\n", f);
    fclose(f);

    wl_init(w);
    wl_load_domains(w, path);
    /* Без классификации цели считаются неизвестными; в этих тестах
       проверяется путь через настоящее устройство. */
    for (int i = 0; i < w->group_count; i++)
        w->groups[i].target = WL_TARGET_IFACE;
}

static void setup(rt_t *r, int ipv6)
{
    rt_init(r);
    snprintf(r->iptables,  sizeof(r->iptables),  "/opt/sbin/iptables");
    snprintf(r->ip6tables, sizeof(r->ip6tables), "/opt/sbin/ip6tables");
    snprintf(r->ip,        sizeof(r->ip),        "/opt/sbin/ip");
    r->ipv6 = ipv6;
}

/* Собирает весь план в одну строку — так проще искать в нём подстроки. */
static void plan_text(const rt_plan_t *p, char *dst, size_t size)
{
    dst[0] = '\0';
    for (int i = 0; i < p->count; i++) {
        char line[512];
        rt_cmd_text(&p->cmds[i], line, sizeof(line));
        strncat(dst, line, size - strlen(dst) - 2);
        strncat(dst, "\n", size - strlen(dst) - 1);
    }
}

static void test_apply_plan(void)
{
    wl_t w;  load_lists(&w);
    rt_t r;  setup(&r, 0);

    rt_plan_t p;
    rt_plan_apply(&p, &r, &w);

    char text[8192];
    plan_text(&p, text, sizeof(text));

    CHECK(p.overflow == 0, "план поместился");

    /* Правила стоят прямо в PREROUTING, как у HydraRoute, и ставятся
       проверкой -C: если стоит — не трогаем. Своей цепочки нет, от
       прежней остаётся только снятие. */
    CHECK(strstr(text, "-N SHADOWFOX") == NULL, "своей цепочки больше нет");
    CHECK(strstr(text, "-t mangle -D PREROUTING -j SHADOWFOX") != NULL &&
          strstr(text, "-t mangle -X SHADOWFOX") != NULL, "прежняя цепочка снимается");

    CHECK(strstr(text,
        "-t mangle -C PREROUTING -m set --match-set Proxy0 dst "
        "-j MARK --set-xmark 0x53460000/0xffff0000") != NULL,
        "метка по совпадению в наборе:\n%s", text);
    CHECK(strstr(text, "--match-set Proxy1 dst") != NULL, "вторая цель");
    CHECK(strstr(text, "--set-xmark 0x53470000/0xffff0000") != NULL,
          "у второй группы своя метка");
    CHECK(strstr(text, "--set-mark ") == NULL, "метка ставится только с маской");
    CHECK(strstr(text, " -A PREROUTING") == NULL, "-A нет: добавление делает ensure после -C");

    int ensures = 0;
    for (int i = 0; i < p.count; i++) if (p.cmds[i].ensure == 1) ensures++;
    CHECK(ensures == 2, "два правила-проверки для двух целей: %d", ensures);

    CHECK(strstr(text, "-4 rule add fwmark 0x53460000/0xffff0000 table 5346")
          != NULL, "правило по метке");
    CHECK(strstr(text, "-4 route replace default dev Proxy0 table 5346")
          != NULL, "маршрут в интерфейс группы");
    CHECK(strstr(text, "dev Proxy1 table 5347") != NULL,
          "вторая группа в свою таблицу и интерфейс");
}

/* Группы одной цели делят набор и правила: правила ставятся один раз. */
static void test_shared_set(void)
{
    char path[160];
    snprintf(path, sizeof(path), "%s/shared.conf", g_dir);
    FILE *f = fopen(path, "w");
    fputs("[Youtube]\ninterface = ShadowFox\nyoutube.com\n"
          "[Google]\ninterface = ShadowFox\ngoogle.com\n"
          "[Steam]\ninterface = Other\nsteampowered.com\n", f);
    fclose(f);

    wl_t w;
    wl_init(&w);
    wl_load_domains(&w, path);
    CHECK(w.group_count == 3, "три группы");
    CHECK(!strcmp(w.groups[0].ipset4, "ShadowFox") && !strcmp(w.groups[1].ipset4, "ShadowFox"),
          "две группы — один набор");
    CHECK(wl_set_owner(&w, 1) == 0 && wl_set_owner(&w, 2) == 2, "владелец набора — первая группа");

    for (int i = 0; i < 3; i++) {
        w.groups[i].target      = WL_TARGET_POLICY;
        w.groups[i].policy_mark = 0xffffaaa + (unsigned)(i == 2);
    }

    rt_t r;  setup(&r, 0);
    rt_plan_t p;
    rt_plan_apply(&p, &r, &w);

    int shadow = 0, other = 0;
    for (int i = 0; i < p.count; i++) {
        char line[512];
        rt_cmd_text(&p.cmds[i], line, sizeof(line));
        if (strstr(line, "--match-set ShadowFox dst")) shadow++;
        if (strstr(line, "--match-set Other dst")) other++;
    }
    CHECK(shadow == 2 && other == 2, "по два правила на набор, не на группу: %d/%d", shadow, other);
}

/* Устаревшие правила находятся по дампу -S и только наши: чужой набор
   не трогается, совпадающее правило не трогается, а правило с другой
   меткой или не той формы — снимается. Hex сверяется без ведущих нулей. */
static void on_stale(const char *rule, void *ctx)
{
    char *acc = ctx;
    strncat(acc, rule, 4000 - strlen(acc) - 2);
    strncat(acc, "\n", 4000 - strlen(acc) - 1);
}

static void test_stale_rules(void)
{
    wl_t w;  load_lists(&w);
    w.groups[0].target      = WL_TARGET_POLICY;
    w.groups[0].policy_mark = 0xffffaaa;
    w.groups[1].target      = WL_TARGET_IFACE;

    const char *dump =
        "-P PREROUTING ACCEPT\n"
        "-A PREROUTING -j _NDM_HOTSPOT_PREROUTING_MANGL\n"
        "-A PREROUTING -m mark ! --mark 0xffffaa0/0xffffff0 -m connmark --mark 0x0 -m set --match-set HydraRoute dst -j CONNMARK --set-xmark 0xffffaaa/0xffffffff\n"
        "-A PREROUTING -m mark ! --mark 0xffffaa0/0xfffffff0 -m connmark --mark 0x0 -m set --match-set Proxy0 dst -j CONNMARK --set-xmark 0xffffaaa/0xffffffff\n"
        "-A PREROUTING -m set --match-set Proxy0 dst -j CONNMARK --restore-mark --nfmask 0xffffffff --ctmask 0xffffffff\n"
        "-A PREROUTING -m mark ! --mark 0xffffaa0/0xfffffff0 -m connmark --mark 0x0 -m set --match-set Proxy0 dst -j CONNMARK --set-xmark 0xffffaab/0xffffffff\n"
        "-A PREROUTING -m set --match-set Proxy1 dst -j MARK --set-xmark 0x53470000/0xffff0000\n"
        "-A PREROUTING -m set --match-set Proxy1 dst -j CONNMARK --restore-mark --nfmask 0xffffffff --ctmask 0xffffffff\n";

    static char acc[4000];
    acc[0] = '\0';
    int n = rt_stale_rules(dump, &w, 0, on_stale, acc);
    CHECK(n == 2, "два устаревших: %d\n%s", n, acc);
    CHECK(strstr(acc, "--set-xmark 0xffffaab/0xffffffff") != NULL, "правило со старой меткой");
    CHECK(strstr(acc, "--match-set Proxy1 dst -j CONNMARK --restore-mark") != NULL,
          "правило политики на наборе устройства");
    CHECK(strstr(acc, "HydraRoute") == NULL, "чужой набор не тронут");
    CHECK(strstr(acc, "--set-xmark 0xffffaaa/") == NULL, "совпадающее не тронуто");

    /* iptables печатает метку устройства без ведущих нулей. */
    w.groups[1].mark = 0x00470000;
    acc[0] = '\0';
    n = rt_stale_rules("-A PREROUTING -m set --match-set Proxy1 dst -j MARK --set-xmark 0x470000/0xffff0000\n",
                       &w, 0, on_stale, acc);
    CHECK(n == 0, "ведущие нули не делают правило чужим: %s", acc);
}

/* Защита порта — своя цепочка в filter, через iptables-restore
   атомарно; правила mangle в restore не идут, они ставятся по -C. */
static void test_atomic_plan(void)
{
    wl_t w;  load_lists(&w);
    rt_t r;  setup(&r, 1);
    snprintf(r.iptables_restore,  sizeof(r.iptables_restore),  "/opt/sbin/iptables-restore");
    snprintf(r.ip6tables_restore, sizeof(r.ip6tables_restore), "/opt/sbin/ip6tables-restore");
    r.guard_port = 1301;

    w.groups[0].target      = WL_TARGET_POLICY;
    w.groups[0].policy_mark = 0xffffaaa;
    w.groups[1].target      = WL_TARGET_IFACE;

    rt_plan_t p;
    rt_plan_apply(&p, &r, &w);
    CHECK(p.overflow == 0, "план поместился");

    char text[8192];
    plan_text(&p, text, sizeof(text));

    CHECK(strstr(p.batch4, "*filter\n:SHADOWFOX_IN - [0:0]\n-A SHADOWFOX_IN ! -i lo -p tcp --dport 1301 -j DROP\n") != NULL,
          "защита порта в restore");
    CHECK(strstr(p.batch4, "*mangle") == NULL, "mangle в restore нет");
    CHECK(p.batch6[0] == '\0', "v6 в restore нет");

    CHECK(strstr(text, "-t mangle -C PREROUTING -m mark ! --mark 0xffffaa0/0xfffffff0 -m connmark --mark 0x0 "
                       "-m set --match-set Proxy0 dst -j CONNMARK --set-xmark 0xffffaaa/0xffffffff") != NULL,
          "правило политики проверкой:\n%s", text);
    CHECK(strstr(text, "-t mangle -C PREROUTING -m set --match-set Proxy0 dst -j CONNMARK --restore-mark") != NULL,
          "возврат метки проверкой");
    CHECK(strstr(text, "ip6tables -t mangle -C PREROUTING -m set --match-set Proxy0v6 dst") != NULL,
          "v6 тем же путём");
    CHECK(strstr(text, "-t filter -C INPUT -j SHADOWFOX_IN") != NULL, "врезка защиты проверяется");

    int inserts = 0;
    for (int i = 0; i < p.count; i++) if (p.cmds[i].ensure == 2) inserts++;
    CHECK(inserts == 1, "одна вставка в начало INPUT");

    rt_plan_t rm;
    rt_plan_remove(&rm, &r, &w);
    CHECK(rm.batch4[0] == '\0', "снятие без restore");
    plan_text(&rm, text, sizeof(text));
    CHECK(strstr(text, "-t mangle -D PREROUTING -m set --match-set Proxy0 dst -j CONNMARK --restore-mark") != NULL,
          "снятие правил командами");
}

static void test_ipv6_added_only_when_asked(void)
{
    wl_t w;  load_lists(&w);

    rt_t r4; setup(&r4, 0);
    rt_plan_t p4;
    rt_plan_apply(&p4, &r4, &w);

    char t4[8192];
    plan_text(&p4, t4, sizeof(t4));
    CHECK(strstr(t4, "ip6tables") == NULL, "без IPv6 команд ip6tables нет");
    CHECK(strstr(t4, "v6 dst") == NULL, "и наборов v6 тоже");

    rt_t r6; setup(&r6, 1);
    rt_plan_t p6;
    rt_plan_apply(&p6, &r6, &w);

    char t6[8192];
    plan_text(&p6, t6, sizeof(t6));
    CHECK(strstr(t6, "ip6tables -t mangle -C PREROUTING") != NULL, "правила v6");
    CHECK(strstr(t6, "--match-set Proxy0v6 dst") != NULL, "набор v6");
    CHECK(strstr(t6, "-6 rule add fwmark") != NULL, "правило v6");
    CHECK(p6.count > p4.count, "с IPv6 команд больше");
}

static void test_remove_plan(void)
{
    wl_t w;  load_lists(&w);
    rt_t r;  setup(&r, 0);

    rt_plan_t p;
    rt_plan_remove(&p, &r, &w);

    char text[8192];
    plan_text(&p, text, sizeof(text));

    CHECK(strstr(text, "-t mangle -D PREROUTING -m set --match-set Proxy0 dst -j MARK") != NULL,
          "правило снято");
    CHECK(strstr(text, "-X SHADOWFOX") != NULL, "прежняя цепочка удаляется");
    CHECK(strstr(text, "rule del fwmark 0x53460000/0xffff0000") != NULL,
          "правило по метке снято");
    CHECK(strstr(text, "route flush table 5346") != NULL, "таблица очищена");

    /* Снятие не должно ничего добавлять. */
    CHECK(strstr(text, "-C PREROUTING") == NULL, "проверок-установок нет");
    CHECK(strstr(text, "rule add") == NULL, "правила не добавляются");
    CHECK(strstr(text, "route replace") == NULL, "маршруты не добавляются");
}

static void test_group_without_interface_skipped(void)
{
    char path[160];
    snprintf(path, sizeof(path), "%s/noiface.conf", g_dir);

    FILE *f = fopen(path, "w");
    /* Группа без интерфейса: заворачивать некуда, правил быть не должно. */
    fputs("[бези]\nexample.com\n[сИ]\ninterface = Proxy0\nok.com\n", f);
    fclose(f);

    wl_t w;
    wl_init(&w);
    wl_load_domains(&w, path);
    for (int i = 0; i < w.group_count; i++)
        w.groups[i].target = WL_TARGET_IFACE;

    rt_t r; setup(&r, 0);
    rt_plan_t p;
    rt_plan_apply(&p, &r, &w);

    char text[8192];
    plan_text(&p, text, sizeof(text));

    CHECK(w.group_count == 2, "обе группы прочитаны");
    CHECK(strstr(text, "table 5346") == NULL,
          "для группы без интерфейса правил нет:\n%s", text);
    CHECK(strstr(text, "table 5347") != NULL, "для группы с интерфейсом есть");
}

static void test_idempotent_shape(void)
{
    /* Повторный запуск не должен плодить дубли: всё, что добавляется,
       сначала снимается либо заменяется. */
    wl_t w;  load_lists(&w);
    rt_t r;  setup(&r, 1);

    rt_plan_t p;
    rt_plan_apply(&p, &r, &w);

    char text[8192];
    plan_text(&p, text, sizeof(text));

    CHECK(strstr(text, "rule add") != NULL, "правила добавляются");
    CHECK(strstr(text, "rule del") != NULL, "и снимаются перед этим");
    CHECK(strstr(text, "route replace") != NULL,
          "маршрут заменяется, а не добавляется вторым");

    for (int i = 0; i < p.count; i++) {
        char line[512];
        rt_cmd_text(&p.cmds[i], line, sizeof(line));
        if (strstr(line, " del ") || strstr(line, "-D ") || strstr(line, "-F ") || strstr(line, "-X "))
            CHECK(p.cmds[i].may_fail == 1,
                  "отсутствие снимаемого не ошибка: %s", line);
    }
}

/* Цель-политика заворачивается совсем иначе: метку назначает роутер,
   ставится она на соединение, и только на новое. */
static void test_policy_target(void)
{
    wl_t w;  load_lists(&w);
    rt_t r;  setup(&r, 0);

    w.groups[0].target      = WL_TARGET_POLICY;
    w.groups[0].policy_mark = 0xffffaaa;
    w.groups[1].target      = WL_TARGET_IFACE;

    rt_plan_t p;
    rt_plan_apply(&p, &r, &w);

    char text[8192];
    plan_text(&p, text, sizeof(text));

    /* Переполнение плана выглядит как отсутствие правил, поэтому
       проверяем его отдельно, а не гадаем по пустому выводу. */
    CHECK(p.overflow == 0, "план поместился, переполнений %d", p.overflow);

    CHECK(strstr(text, "-j CONNMARK --set-xmark 0xffffaaa/0xffffffff") != NULL,
          "метка политики ставится на соединение:\n%s", text);
    /* Только новые соединения: дальше работает восстановление метки. */
    CHECK(strstr(text, "-m connmark --mark 0x0") != NULL,
          "метится только соединение без метки");
    /* И только те пакеты, что ещё не отданы другой политике. */
    CHECK(strstr(text, "-m mark ! --mark 0xffffaa0/0xfffffff0") != NULL,
          "чужие политики не перехватываются");
    CHECK(strstr(text, "--restore-mark") != NULL, "метка переносится на пакет");

    /* Для политики своей таблицы не нужно — маршрутизирует роутер. */
    CHECK(strstr(text, "table 5346") == NULL,
          "политике не создаётся своя таблица");
    /* А для группы-устройства всё по-прежнему. */
    CHECK(strstr(text, "dev Proxy1 table 5347") != NULL,
          "устройство маршрутизируется по-старому");
}

/* Пока метка политики не получена, правил быть не должно: пустая метка
   в CONNMARK увела бы трафик в никуда. */
static void test_policy_without_mark(void)
{
    wl_t w;  load_lists(&w);
    rt_t r;  setup(&r, 0);

    w.groups[0].target      = WL_TARGET_POLICY;
    w.groups[0].policy_mark = 0;
    w.groups[1].target      = WL_TARGET_POLICY;
    w.groups[1].policy_mark = 0;

    rt_plan_t p;
    rt_plan_apply(&p, &r, &w);

    char text[8192];
    plan_text(&p, text, sizeof(text));
    CHECK(strstr(text, "CONNMARK") == NULL,
          "без метки правил нет:\n%s", text);
}

/* Разбор счётчиков iptables. Проверка была ошибочной дважды подряд, и
   оба раза молча: сначала считалось только последнее совпадение, потом
   строка группы, заворачивающей на интерфейс, не попадала под шаблон
   вовсе. Снаружи это выглядело как «трафик не метится». */
static void test_counters(void)
{
    /* Настоящая форма вывода `iptables -t mangle -L PREROUTING -v -n -x`.
       Рядом стоят правила HydraRoute на его наборе — их считать нельзя.
       Действие для политики печатается как «CONNMARK set», а для группы
       на интерфейс — как «MARK xset»: маска у второй не полная. */
    wl_t w;  load_lists(&w);
    const char *out =
        "Chain PREROUTING (policy ACCEPT 1 packets, 2 bytes)\n"
        "    pkts      bytes target     prot opt in     out     source               destination\n"
        "    9999   999999 CONNMARK   all  --  *      *       0.0.0.0/0            0.0.0.0/0            "
        "mark match ! 0x10/0xfffffff0 connmark match 0x0 match-set HydraRoute dst CONNMARK xset 0x11/0xffffffff\n"
        "      17     1020 CONNMARK   all  --  *      *       0.0.0.0/0            0.0.0.0/0            "
        "mark match ! 0x10/0xfffffff0 connmark match 0x0 match-set Proxy0 dst CONNMARK xset 0x11/0xffffffff\n"
        "     412    31000 CONNMARK   all  --  *      *       0.0.0.0/0            0.0.0.0/0            "
        "match-set Proxy0 dst CONNMARK restore mask 0xffffffff\n"
        "       5      300 MARK       all  --  *      *       0.0.0.0/0            0.0.0.0/0            "
        "match-set Proxy1 dst MARK xset 0x10000/0xffff0000\n";

    unsigned long marked = 0, restored = 0;
    rt_parse_counters(out, &w, &marked, &restored);

    CHECK(marked == 22, "помечено сложено по нашим правилам, чужое не считано: %lu", marked);
    CHECK(restored == 412, "восстановлено: %lu", restored);

    marked = restored = 0;
    rt_parse_counters("Chain PREROUTING (policy ACCEPT)\n pkts bytes target\n",
                      &w, &marked, &restored);
    CHECK(marked == 0 && restored == 0, "пустая цепочка даёт нули");

    rt_parse_counters(NULL, &w, &marked, &restored);
    CHECK(marked == 0 && restored == 0, "NULL не ломает разбор");
}

/* План на предельное число групп обязан помещаться. Раньше предел стоял
   в 128 команд и переполнялся на тринадцатой группе с IPv6, а
   переполненный план отвергается целиком — не маршрутизировалась ни
   одна группа. */
static void test_full_house_fits(void)
{
    char path[160];
    snprintf(path, sizeof(path), "%s/full.conf", g_dir);

    FILE *f = fopen(path, "w");
    for (int i = 0; i < WL_GROUPS_MAX; i++)
        fprintf(f, "[g%d]\ninterface = Proxy%d\nexample%d.net\n", i, i, i);
    fclose(f);

    wl_t w;
    wl_init(&w);
    wl_load_domains(&w, path);
    CHECK(w.group_count == WL_GROUPS_MAX, "групп %d", w.group_count);
    for (int i = 0; i < w.group_count; i++) w.groups[i].target = WL_TARGET_IFACE;

    rt_t r;  setup(&r, 1);
    rt_plan_t p;
    rt_plan_apply(&p, &r, &w);
    CHECK(p.overflow == 0, "план на %d групп с IPv6 не поместился: %d команд",
          WL_GROUPS_MAX, p.count);

    rt_plan_remove(&p, &r, &w);
    CHECK(p.overflow == 0, "план снятия не поместился: %d", p.count);
}

/* Порт ядра закрыт от сети: правило в своей цепочке filter, только для
   пришедшего не с петли — прокси-клиент роутера ходит через lo и под
   него не попадает. Ставится и снимается общим планом. */
static void test_guard_port(void)
{
    wl_t w;  load_lists(&w);
    rt_t r;  setup(&r, 0);
    r.guard_port = 1301;

    rt_plan_t p;
    rt_plan_apply(&p, &r, &w);

    char text[16384];
    plan_text(&p, text, sizeof(text));

    CHECK(strstr(text, "-t filter -N SHADOWFOX_IN") != NULL, "цепочка создаётся");
    CHECK(strstr(text, "SHADOWFOX_IN ! -i lo -p tcp --dport 1301 -j DROP") != NULL,
          "tcp закрыт для всего, кроме петли");
    CHECK(strstr(text, "SHADOWFOX_IN ! -i lo -p udp --dport 1301 -j DROP") != NULL,
          "udp тоже");
    CHECK(strstr(text, "-I INPUT 1 -j SHADOWFOX_IN") != NULL, "врезка в начало INPUT");
    CHECK(p.overflow == 0, "план помещается");

    rt_plan_remove(&p, &r, &w);
    plan_text(&p, text, sizeof(text));
    CHECK(strstr(text, "-X SHADOWFOX_IN") != NULL, "снятие убирает цепочку");
    CHECK(strstr(text, "-D INPUT -j SHADOWFOX_IN") != NULL, "и врезку");

    /* Без порта — ни одной команды про filter. */
    r.guard_port = 0;
    rt_plan_apply(&p, &r, &w);
    plan_text(&p, text, sizeof(text));
    CHECK(strstr(text, "SHADOWFOX_IN") == NULL, "без порта цепочки нет");
}

int main(void)
{
    printf("check_routing " VERSION "\n");

    char tpl[] = "/tmp/shadowfox-rt-XXXXXX";
    if (!mkdtemp(tpl)) { printf("не создать временный каталог\n"); return 1; }
    snprintf(g_dir, sizeof(g_dir), "%s", tpl);

    test_apply_plan();
    test_shared_set();
    test_stale_rules();
    test_atomic_plan();
    test_ipv6_added_only_when_asked();
    test_remove_plan();
    test_group_without_interface_skipped();
    test_idempotent_shape();
    test_policy_target();
    test_policy_without_mark();
    test_full_house_fits();
    test_guard_port();
    test_counters();

    char cmd[160];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", g_dir);
    if (system(cmd) != 0) printf("  (не удалось убрать %s)\n", g_dir);

    if (failures) {
        printf("ПРОВАЛЕНО проверок: %d\n", failures);
        return 1;
    }
    printf("все проверки пройдены\n");
    return 0;
}
