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

    /* Работаем в своей цепочке: её можно чистить целиком, не задевая
       правила HydraRoute и прошивки в PREROUTING. */
    CHECK(strstr(text, "-t mangle -N SHADOWFOX") != NULL, "своя цепочка");
    CHECK(strstr(text, "-t mangle -F SHADOWFOX") != NULL, "цепочка чистится");

    CHECK(strstr(text,
        "-A SHADOWFOX -m set --match-set sf4_0_youtube dst "
        "-j MARK --set-xmark 0x53460000/0xffff0000") != NULL,
        "метка по совпадению в наборе:\n%s", text);
    CHECK(strstr(text, "--match-set sf4_1_soc dst") != NULL, "вторая группа");
    CHECK(strstr(text, "--set-xmark 0x53470000/0xffff0000") != NULL,
          "у второй группы своя метка");

    /* set-xmark с маской, а не set-mark: младшая половина метки
       принадлежит другим программам, включая hrneo. */
    CHECK(strstr(text, "--set-mark ") == NULL,
          "метка ставится только с маской");

    CHECK(strstr(text, "-4 rule add fwmark 0x53460000/0xffff0000 table 5346")
          != NULL, "правило по метке");
    CHECK(strstr(text, "-4 route replace default dev Proxy0 table 5346")
          != NULL, "маршрут в интерфейс группы");
    CHECK(strstr(text, "dev Proxy1 table 5347") != NULL,
          "вторая группа в свою таблицу и интерфейс");

    /* Врезка снимается перед вставкой, иначе повторный запуск наплодит
       дублей в PREROUTING. */
    CHECK(strstr(text, "-D PREROUTING -j SHADOWFOX") != NULL, "снятие врезки");
    CHECK(strstr(text, "-A PREROUTING -j SHADOWFOX") != NULL, "врезка");

    const char *del = strstr(text, "-D PREROUTING -j SHADOWFOX");
    const char *ins = strstr(text, "-A PREROUTING -j SHADOWFOX");
    CHECK(del && ins && del < ins, "снятие идёт раньше вставки");
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
    CHECK(strstr(t4, "sf6_") == NULL, "и наборов v6 тоже");

    rt_t r6; setup(&r6, 1);
    rt_plan_t p6;
    rt_plan_apply(&p6, &r6, &w);

    char t6[8192];
    plan_text(&p6, t6, sizeof(t6));
    CHECK(strstr(t6, "ip6tables -t mangle -N SHADOWFOX") != NULL,
          "цепочка v6");
    CHECK(strstr(t6, "--match-set sf6_0_youtube dst") != NULL, "набор v6");
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

    CHECK(strstr(text, "-D PREROUTING -j SHADOWFOX") != NULL, "врезка снята");
    CHECK(strstr(text, "-X SHADOWFOX") != NULL, "цепочка удалена");
    CHECK(strstr(text, "rule del fwmark 0x53460000/0xffff0000") != NULL,
          "правило по метке снято");
    CHECK(strstr(text, "route flush table 5346") != NULL, "таблица очищена");

    /* Снятие не должно ничего добавлять. */
    CHECK(strstr(text, "-A PREROUTING -j SHADOWFOX") == NULL,
          "врезка не ставится");
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
        if (strstr(line, " del ") || strstr(line, "-D ") || strstr(line, "-N "))
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
    /* Настоящая форма вывода `iptables -t mangle -L SHADOWFOX -v -n -x`.
       Действие для политики печатается как «CONNMARK set», а для группы
       на интерфейс — как «MARK xset»: маска у второй не полная. */
    const char *out =
        "Chain SHADOWFOX (1 references)\n"
        "    pkts      bytes target     prot opt in     out     source               destination\n"
        "      17     1020 CONNMARK   all  --  *      *       0.0.0.0/0            0.0.0.0/0            "
        "mark match ! 0x10/0xfffffff0 connmark match 0x0 match-set sf4_0_youtube dst CONNMARK xset 0x11/0xffffffff\n"
        "     412    31000 CONNMARK   all  --  *      *       0.0.0.0/0            0.0.0.0/0            "
        "match-set sf4_0_youtube dst CONNMARK restore mask 0xffffffff\n"
        "       5      300 MARK       all  --  *      *       0.0.0.0/0            0.0.0.0/0            "
        "match-set sf4_1_discord dst MARK xset 0x10000/0xffff0000\n";

    unsigned long marked = 0, restored = 0;
    rt_parse_counters(out, &marked, &restored);

    CHECK(marked == 22, "помечено сложено по всем правилам: %lu", marked);
    CHECK(restored == 412, "восстановлено: %lu", restored);

    /* Пустой вывод и заголовок без правил не должны ничего насчитать. */
    marked = restored = 0;
    rt_parse_counters("Chain SHADOWFOX (1 references)\n pkts bytes target\n",
                      &marked, &restored);
    CHECK(marked == 0 && restored == 0, "пустая цепочка даёт нули");

    rt_parse_counters(NULL, &marked, &restored);
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
