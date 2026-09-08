#include "routing.h"
#include "log.h"
#include "proc.h"
#include "util.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *IPTABLES_CANDIDATES[] = {
    "/opt/sbin/iptables", "/usr/sbin/iptables", "/sbin/iptables", NULL
};
static const char *IP6TABLES_CANDIDATES[] = {
    "/opt/sbin/ip6tables", "/usr/sbin/ip6tables", "/sbin/ip6tables", NULL
};
static const char *IPTR_CANDIDATES[] = {
    "/opt/sbin/iptables-restore", "/usr/sbin/iptables-restore", "/sbin/iptables-restore", NULL
};
static const char *IP6TR_CANDIDATES[] = {
    "/opt/sbin/ip6tables-restore", "/usr/sbin/ip6tables-restore", "/sbin/ip6tables-restore", NULL
};
static const char *IP_CANDIDATES[] = {
    "/opt/sbin/ip", "/opt/bin/ip", "/usr/sbin/ip", "/sbin/ip", NULL
};

static int find_first(const char **list, char *dst, unsigned size)
{
    dst[0] = '\0';
    for (int i = 0; list[i]; i++) {
        if (access(list[i], X_OK) == 0) {
            str_copy(dst, size, list[i]);
            return 1;
        }
    }
    return 0;
}

void rt_init(rt_t *r)
{
    memset(r, 0, sizeof(*r));
    r->timeout = 15;
    r->ipv6    = 1;
}

int rt_find_bins(rt_t *r)
{
    if (!r) return 0;

    int ok = find_first(IPTABLES_CANDIDATES, r->iptables, sizeof(r->iptables));
    ok &= find_first(IP_CANDIDATES, r->ip, sizeof(r->ip));

    /* ip6tables может отсутствовать — тогда просто не трогаем IPv6. */
    if (!find_first(IP6TABLES_CANDIDATES, r->ip6tables, sizeof(r->ip6tables)))
        r->ipv6 = 0;

    /* restore не обязателен: без него — прежний путь, по команде. */
    find_first(IPTR_CANDIDATES, r->iptables_restore, sizeof(r->iptables_restore));
    find_first(IP6TR_CANDIDATES, r->ip6tables_restore, sizeof(r->ip6tables_restore));

    return ok;
}

const char *rt_cmd_text(const rt_cmd_t *c, char *dst, unsigned size)
{
    if (!c || !dst || !size) return "";

    dst[0] = '\0';
    unsigned used = 0;

    for (int i = 0; i < c->argc; i++) {
        int n = snprintf(dst + used, size - used, "%s%s",
                         i ? " " : "", c->argv[i]);
        if (n < 0 || (unsigned)n >= size - used) break;
        used += (unsigned)n;
    }
    return dst;
}

/* Добавляет команду в план. Аргументы — список строк, оканчивающийся NULL. */
static void add(rt_plan_t *p, int may_fail, const char *const *args)
{
    if (!p) return;
    if (p->count >= RT_CMDS_MAX) { p->overflow++; return; }

    rt_cmd_t *c = &p->cmds[p->count];
    memset(c, 0, sizeof(*c));
    c->may_fail = may_fail;

    for (int i = 0; args[i]; i++) {
        if (i >= RT_ARGS_MAX) { p->overflow++; return; }
        if (str_copy(c->argv[i], RT_ARG_LEN, args[i]) != 0) {
            p->overflow++;
            return;
        }
        c->argc = i + 1;
    }

    p->count++;
}

static void add_ensure(rt_plan_t *p, int how, const char *const *args)
{
    int before = p->count;
    add(p, 1, args);
    if (p->count > before) p->cmds[p->count - 1].ensure = how;
}

/* Дописывает строку в текст для iptables-restore. Переполнение помечает
   план негодным: полцепочки хуже, чем ничего. */
static void batch(rt_plan_t *p, char *buf, const char *line)
{
    size_t used = strlen(buf), len = strlen(line);
    if (used + len + 1 >= RT_BATCH_BYTES) { p->overflow++; return; }
    memcpy(buf + used, line, len + 1);
}

/* Метка пишется с маской: младшая половина принадлежит другим
   программам, затирать её нельзя. */
static void mark_text(char *dst, unsigned size, unsigned mark)
{
    snprintf(dst, size, "0x%08x/0x%08x", mark, WL_MARK_MASK);
}

/* Текст правила для набора — общий и для плана, и для сверки с дампом
   `-S PREROUTING`: аргументы после «-A PREROUTING». kind: 0 — метка
   политики на соединение, 1 — возврат метки на пакет, 2 — метка
   устройства. */
static void rule_text(char *dst, size_t size, int kind, const char *set,
                      unsigned policy_mark, unsigned mark)
{
    switch (kind) {
    case 0:
        snprintf(dst, size,
                 "-m mark ! --mark 0x%x/0xfffffff0 -m connmark --mark 0x0 "
                 "-m set --match-set %s dst -j CONNMARK --set-xmark 0x%x/0xffffffff",
                 policy_mark & 0xFFFFFFF0u, set, policy_mark);
        break;
    case 1:
        snprintf(dst, size,
                 "-m set --match-set %s dst -j CONNMARK --restore-mark "
                 "--nfmask 0xffffffff --ctmask 0xffffffff", set);
        break;
    default:
        snprintf(dst, size,
                 "-m set --match-set %s dst -j MARK --set-xmark 0x%08x/0x%08x",
                 set, mark, WL_MARK_MASK);
        break;
    }
}

/* Строку правила — в план: «tables -t mangle <действие> PREROUTING …».
   Для установки действие -C с ensure: поставить только если нет. */
static void add_rule(rt_plan_t *p, const char *tables, const char *action,
                     const char *rule, int ensure, int may_fail)
{
    const char *args[RT_ARGS_MAX + 1];
    char        copy[RT_ARG_LEN * 8];
    int         n = 0;

    args[n++] = tables; args[n++] = "-t"; args[n++] = "mangle";
    args[n++] = action; args[n++] = "PREROUTING";

    str_copy(copy, sizeof(copy), rule);
    char *save = NULL;
    for (char *t = strtok_r(copy, " ", &save); t && n < RT_ARGS_MAX; t = strtok_r(NULL, " ", &save))
        args[n++] = t;
    args[n] = NULL;

    int before = p->count;
    add(p, may_fail, args);
    if (ensure && p->count > before) p->cmds[p->count - 1].ensure = 1;
}

/* Правила стоят прямо в PREROUTING, как у HydraRoute: по два на набор
   политики, по одному на набор устройства, наборы общие на цель.
   Ставятся проверкой -C и добавляются только при отсутствии — ни
   сброса, ни зазора. Своей цепочки больше нет; от прежней остаётся
   только снятие, чтобы обновление не оставило её висеть. */
static void plan_family(rt_plan_t *p, const char *tables, const char *ipbin,
                        const char *ipflag, const wl_t *w, int v6, int remove)
{
    const char *table_arg = "mangle";

    /* Прежняя цепочка SHADOWFOX: снять врезку, очистить, удалить. */
    const char *unhook[] = { tables, "-t", table_arg, "-D", "PREROUTING", "-j", RT_CHAIN, NULL };
    add(p, 1, unhook);
    const char *fl[] = { tables, "-t", table_arg, "-F", RT_CHAIN, NULL };
    add(p, 1, fl);
    const char *rm[] = { tables, "-t", table_arg, "-X", RT_CHAIN, NULL };
    add(p, 1, rm);

    for (int i = 0; i < w->group_count; i++) {
        const wl_group_t *g = &w->groups[i];
        if (!g->iface[0]) continue;
        if (!g->enabled) continue;      /* выключенная группа трафик не метит */
        if (wl_set_owner(w, i) != i) continue;   /* набор общий — правила одни */

        const char *set = v6 ? g->ipset6 : g->ipset4;
        char rule[320];

        if (g->target == WL_TARGET_POLICY) {
            if (!g->policy_mark) continue;   /* метку ещё не узнали */
            rule_text(rule, sizeof(rule), 0, set, g->policy_mark, 0);
            add_rule(p, tables, remove ? "-D" : "-C", rule, !remove, 1);
            rule_text(rule, sizeof(rule), 1, set, g->policy_mark, 0);
            add_rule(p, tables, remove ? "-D" : "-C", rule, !remove, 1);
            continue;
        }

        /* Настоящее устройство: своя метка и своя таблица. */
        rule_text(rule, sizeof(rule), 2, set, 0, g->mark);
        add_rule(p, tables, remove ? "-D" : "-C", rule, !remove, 1);

        char mark[32];
        mark_text(mark, sizeof(mark), g->mark);
        char table[16];
        snprintf(table, sizeof(table), "%u", g->table);

        /* Правило по метке пересоздаём: повторный add завёл бы дубль. */
        const char *rule_del[] = {
            ipbin, ipflag, "rule", "del", "fwmark", mark, "table", table, NULL
        };
        add(p, 1, rule_del);

        const char *route_del[] = {
            ipbin, ipflag, "route", "flush", "table", table, NULL
        };
        add(p, 1, route_del);

        if (!remove) {
            const char *rule_add[] = {
                ipbin, ipflag, "rule", "add", "fwmark", mark,
                "table", table, NULL
            };
            add(p, 0, rule_add);

            const char *route_add[] = {
                ipbin, ipflag, "route", "replace", "default",
                "dev", g->iface, "table", table, NULL
            };
            add(p, 0, route_add);
        }
    }
}

/* Нормализация правила для сверки с дампом: iptables печатает hex без
   ведущих нулей (0x3001, а не 0x00003001), а мы пишем по-своему. */
static void normalize_rule(const char *in, char *out, size_t size)
{
    char copy[512];
    str_copy(copy, sizeof(copy), in);
    out[0] = '\0';
    size_t used = 0;
    char *save = NULL;
    for (char *t = strtok_r(copy, " ", &save); t; t = strtok_r(NULL, " ", &save)) {
        char tok[96];
        if (t[0] == '0' && (t[1] == 'x' || t[1] == 'X')) {
            /* 0xAAAA/0xBBBB: каждую часть без ведущих нулей, строчными. */
            size_t o = 0;
            for (char *q = t; *q && o + 1 < sizeof(tok); ) {
                if (q[0] == '0' && (q[1] == 'x' || q[1] == 'X')) {
                    tok[o++] = '0'; tok[o++] = 'x'; q += 2;
                    while (*q == '0' && isxdigit((unsigned char)q[1])) q++;
                    continue;
                }
                tok[o++] = (char)tolower((unsigned char)*q++);
            }
            tok[o] = '\0';
        } else {
            str_copy(tok, sizeof(tok), t);
        }
        int n = snprintf(out + used, size - used, "%s%s", used ? " " : "", tok);
        if (n < 0 || (size_t)n >= size - used) break;
        used += (size_t)n;
    }
}

int rt_stale_rules(const char *dump, const wl_t *w, int v6,
                   void (*cb)(const char *rule, void *ctx), void *ctx)
{
    if (!dump || !w || !cb) return 0;

    int stale = 0;
    const char *line = dump;
    for (;;) {
        const char *nl  = strchr(line, '\n');
        size_t      len = nl ? (size_t)(nl - line) : strlen(line);

        if (len > 14 && !strncmp(line, "-A PREROUTING ", 14)) {
            char rule[512];
            size_t n = len - 14;
            if (n >= sizeof(rule)) n = sizeof(rule) - 1;
            memcpy(rule, line + 14, n);
            rule[n] = '\0';

            /* Наше ли: в правиле один из наших наборов. */
            int owner = -1;
            for (int i = 0; i < w->group_count && owner < 0; i++) {
                const wl_group_t *g = &w->groups[i];
                if (!g->iface[0]) continue;
                char needle[WL_SETNAME_MAX + 16];
                snprintf(needle, sizeof(needle), "--match-set %s ", v6 ? g->ipset6 : g->ipset4);
                if (strstr(rule, needle)) owner = i;
            }

            if (owner >= 0) {
                const wl_group_t *g = &w->groups[owner];
                const char *set = v6 ? g->ipset6 : g->ipset4;
                char want[3][320], have[512], wantn[512];
                int  kinds = 0, ok = 0;

                if (g->enabled && g->target == WL_TARGET_POLICY && g->policy_mark) {
                    rule_text(want[kinds++], 320, 0, set, g->policy_mark, 0);
                    rule_text(want[kinds++], 320, 1, set, g->policy_mark, 0);
                } else if (g->enabled && g->target == WL_TARGET_IFACE) {
                    rule_text(want[kinds++], 320, 2, set, 0, g->mark);
                }

                normalize_rule(rule, have, sizeof(have));
                for (int k = 0; k < kinds && !ok; k++) {
                    normalize_rule(want[k], wantn, sizeof(wantn));
                    ok = !strcmp(have, wantn);
                }
                if (!ok) { cb(rule, ctx); stale++; }
            }
        }

        if (!nl) break;
        line = nl + 1;
    }
    return stale;
}

typedef struct { const rt_t *r; const char *tables; int removed; } prune_ctx_t;

static void prune_one(const char *rule, void *ctx)
{
    prune_ctx_t *c = ctx;
    rt_plan_t   *p = malloc(sizeof(*p));
    if (!p) return;
    memset(p, 0, sizeof(*p));
    add_rule(p, c->tables, "-D", rule, 0, 1);
    char err[256];
    if (rt_run(p, c->r, err, sizeof(err)) == 0) c->removed++;
    free(p);
}

int rt_prune_stale(const rt_t *r, const wl_t *w)
{
    if (!r || !w) return 0;

    const char *bins[2] = { r->iptables, r->ip6tables };
    int removed = 0;

    for (int f = 0; f < 2; f++) {
        if (!bins[f][0]) continue;
        if (f == 1 && !r->ipv6) continue;

        char binbuf[RT_BIN_MAX];
        str_copy(binbuf, sizeof(binbuf), bins[f]);
        char t[] = "-t", mangle[] = "mangle", S[] = "-S", chain[] = "PREROUTING";
        char *argv[] = { binbuf, t, mangle, S, chain, NULL };

        static char out[64 * 1024];
        int trunc = 0;
        if (proc_run_capture(argv, out, sizeof(out), r->timeout, &trunc) != 0 || trunc) continue;

        prune_ctx_t c = { r, bins[f], 0 };
        rt_stale_rules(out, w, f, prune_one, &c);
        removed += c.removed;
    }
    return removed;
}

/* Порт ядра SOCKS5 — без пароля, на LAN-адресе роутера, с UDP: так
   его ждёт прокси-клиент Keenetic. Но тогда любое устройство сегмента
   могло слать через туннель что угодно, минуя политику и наборы, — с
   выходом с адреса VPS. Снято на живом роутере: единственный клиент
   порта — сам роутер, а соединение с самого себя идёт через lo, не
   через br0. Поэтому закрываем порт для всего, что пришло не с петли,
   и прокси-клиент под правило не попадает. Своя цепочка в filter, с
   врезкой в начало INPUT: правило точечное, чужому не мешает. */
static void plan_guard(rt_plan_t *p, const char *tables, int port, int remove,
                       char *restore)
{
    if (port <= 0) return;

    char dport[16];   /* %d по максимуму типа — десять знаков */
    snprintf(dport, sizeof(dport), "%d", port);

    if (!remove && restore) {
        char line[160];
        batch(p, restore, "*filter\n:" RT_GUARD " - [0:0]\n");
        snprintf(line, sizeof(line),
                 "-A " RT_GUARD " ! -i lo -p tcp --dport %s -j DROP\n", dport);
        batch(p, restore, line);
        snprintf(line, sizeof(line),
                 "-A " RT_GUARD " ! -i lo -p udp --dport %s -j DROP\n", dport);
        batch(p, restore, line);
        batch(p, restore, "COMMIT\n");
        const char *chk[] = {
            tables, "-t", "filter", "-C", "INPUT", "-j", RT_GUARD, NULL
        };
        add_ensure(p, 2, chk);
        return;
    }

    const char *unhook[] = {
        tables, "-t", "filter", "-D", "INPUT", "-j", RT_GUARD, NULL
    };

    if (remove) {
        add(p, 1, unhook);
        const char *fl[] = { tables, "-t", "filter", "-F", RT_GUARD, NULL };
        add(p, 1, fl);
        const char *rm[] = { tables, "-t", "filter", "-X", RT_GUARD, NULL };
        add(p, 1, rm);
        return;
    }

    const char *mk[] = { tables, "-t", "filter", "-N", RT_GUARD, NULL };
    add(p, 1, mk);
    const char *fl[] = { tables, "-t", "filter", "-F", RT_GUARD, NULL };
    add(p, 0, fl);

    const char *tcp[] = {
        tables, "-t", "filter", "-A", RT_GUARD, "!", "-i", "lo",
        "-p", "tcp", "--dport", dport, "-j", "DROP", NULL
    };
    add(p, 0, tcp);
    const char *udp[] = {
        tables, "-t", "filter", "-A", RT_GUARD, "!", "-i", "lo",
        "-p", "udp", "--dport", dport, "-j", "DROP", NULL
    };
    add(p, 0, udp);

    add(p, 1, unhook);
    const char *hook[] = {
        tables, "-t", "filter", "-I", "INPUT", "1", "-j", RT_GUARD, NULL
    };
    add(p, 0, hook);
}

static void plan_both(rt_plan_t *p, const rt_t *r, const wl_t *w, int remove)
{
    if (!p || !r || !w) return;
    memset(p, 0, sizeof(*p));

    /* В сухом прогоне на машине без iptables пути пусты, и команда
       выглядела бы как начинающаяся с пробела. Лучше сказать прямо. */
    const char *ipt = r->iptables[0] ? r->iptables : "<нет:iptables>";
    const char *ipb = r->ip[0]       ? r->ip       : "<нет:ip>";

    char *b4 = (!remove && r->iptables_restore[0]) ? p->batch4 : NULL;

    plan_family(p, ipt, ipb, "-4", w, 0, remove);
    if (r->ipv6 && r->ip6tables[0])
        plan_family(p, r->ip6tables, ipb, "-6", w, 1, remove);

    /* Ядро слушает на адресе IPv4, поэтому и закрываем только его. */
    plan_guard(p, ipt, r->guard_port, remove, b4);
}

void rt_plan_apply(rt_plan_t *p, const rt_t *r, const wl_t *w)
{
    plan_both(p, r, w, 0);
}

void rt_plan_remove(rt_plan_t *p, const rt_t *r, const wl_t *w)
{
    plan_both(p, r, w, 1);
}

int rt_run(const rt_plan_t *p, const rt_t *r, char *err, unsigned err_size)
{
    if (!p || !r) return -1;

    if (p->overflow) {
        if (err && err_size)
            str_copy(err, err_size, "план правил не поместился");
        return -1;
    }

    /* Сначала атомарные подмены цепочек, потом команды: врезка ставится
       уже в наполненную цепочку. */
    const char *bins[2]  = { r->iptables_restore, r->ip6tables_restore };
    const char *texts[2] = { p->batch4, p->batch6 };
    for (int f = 0; f < 2; f++) {
        if (!texts[f][0] || !bins[f][0]) continue;
        char binbuf[RT_BIN_MAX], noflush[] = "--noflush";
        str_copy(binbuf, sizeof(binbuf), bins[f]);
        char *argv[] = { binbuf, noflush, NULL };
        char  out[512];
        int   rc = proc_run_input(argv, texts[f], out, sizeof(out), r->timeout);
        if (rc != 0) {
            if (err && err_size)
                snprintf(err, err_size, "%s --noflush -> %d: %s", bins[f], rc, out);
            return -1;
        }
    }

    for (int i = 0; i < p->count; i++) {
        const rt_cmd_t *c = &p->cmds[i];
        if (!c->argc) continue;

        char *argv[RT_ARGS_MAX + 2];
        char  copy[RT_ARGS_MAX + 1][RT_ARG_LEN];
        int   argc = c->argc;

        for (int k = 0; k < c->argc; k++) {
            memcpy(copy[k], c->argv[k], RT_ARG_LEN);
            argv[k] = copy[k];
        }
        argv[argc] = NULL;

        char out[512];
        int  rc = proc_run(argv, out, sizeof(out), r->timeout);

        if (c->ensure && rc != 0) {
            /* Проверка не прошла — ставим. -C стоит на месте действия. */
            int at = -1;
            for (int k = 0; k < argc; k++) if (!strcmp(copy[k], "-C")) at = k;
            if (at < 0) continue;
            if (c->ensure == 2 && argc < RT_ARGS_MAX) {
                /* -I <цепочка> 1: сдвигаем хвост на одну позицию. */
                for (int k = argc; k > at + 2; k--) memcpy(copy[k], copy[k - 1], RT_ARG_LEN);
                str_copy(copy[at + 2], RT_ARG_LEN, "1");
                argc++;
                for (int k = 0; k < argc; k++) argv[k] = copy[k];
                argv[argc] = NULL;
                str_copy(copy[at], RT_ARG_LEN, "-I");
            } else {
                str_copy(copy[at], RT_ARG_LEN, "-A");
            }
            rc = proc_run(argv, out, sizeof(out), r->timeout);
            if (rc != 0) {
                char text[512];
                if (err && err_size)
                    snprintf(err, err_size, "%s -> %d: %s",
                             rt_cmd_text(c, text, sizeof(text)), rc, out);
                return -1;
            }
            continue;
        }

        if (rc != 0 && !c->may_fail) {
            char text[512];
            if (err && err_size)
                snprintf(err, err_size, "%s -> %d: %s",
                         rt_cmd_text(c, text, sizeof(text)), rc, out);
            return -1;
        }
    }

    return 0;
}

/* Наше ли правило в строке -L: в ней упомянут один из наших наборов.
   Без фильтра в PREROUTING считались бы и правила HydraRoute рядом. */
static int line_is_ours(const char *line, size_t len, const wl_t *w)
{
    if (!w) return 1;
    for (int i = 0; i < w->group_count; i++) {
        const wl_group_t *g = &w->groups[i];
        if (!g->iface[0]) continue;
        char n4[WL_SETNAME_MAX + 16], n6[WL_SETNAME_MAX + 16];
        snprintf(n4, sizeof(n4), "match-set %s ", g->ipset4);
        snprintf(n6, sizeof(n6), "match-set %s ", g->ipset6);
        if (memmem(line, len, n4, strlen(n4)) || memmem(line, len, n6, strlen(n6))) return 1;
    }
    return 0;
}

void rt_parse_counters(const char *text, const wl_t *w, unsigned long *marked,
                       unsigned long *restored)
{
    if (!text) return;

    const char *line = text;
    for (;;) {
        const char *nl  = strchr(line, '\n');
        size_t      len = nl ? (size_t)(nl - line) : strlen(line);

        long pkts = 0;
        if (sscanf(line, " %ld", &pkts) == 1 && pkts >= 0 && line_is_ours(line, len, w)) {
            /* Искать надо в пределах строки, а не до конца текста:
               strstr про перевод строки не знает, и правило пометки
               находило слово «restore» из следующей строки. Поймано
               тестом сразу после написания. */
            int is_restore = memmem(line, len, "restore", 7) != NULL;
            int is_mark    = memmem(line, len, "MARK", 4) != NULL;

            /* Порядок важен: строка восстановления метки тоже содержит
               «MARK». */
            if (is_restore) {
                if (restored) *restored += (unsigned long)pkts;
            } else if (is_mark) {
                if (marked) *marked += (unsigned long)pkts;
            }
        }

        if (!nl) break;
        line = nl + 1;
    }
}

int rt_counters(const rt_t *r, const wl_t *w, unsigned long *marked, unsigned long *restored)
{
    if (!r) return -1;

    if (marked)   *marked = 0;
    if (restored) *restored = 0;

    const char *bins[2] = { r->iptables, r->ip6tables };
    int found = 0;

    for (int i = 0; i < 2; i++) {
        if (!bins[i][0]) continue;

        char binbuf[RT_BIN_MAX];
        str_copy(binbuf, sizeof(binbuf), bins[i]);

        char t[] = "-t", mangle[] = "mangle", L[] = "-L";
        char chain[] = "PREROUTING", v[] = "-v", n[] = "-n", x[] = "-x";
        char *argv[] = { binbuf, t, mangle, L, chain, v, n, x, NULL };

        static char out[64 * 1024];
        if (proc_run(argv, out, sizeof(out), 5) != 0) continue;

        found = 1;
        rt_parse_counters(out, w, marked, restored);
    }

    return found ? 0 : -1;
}
