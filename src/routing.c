#include "routing.h"
#include "log.h"
#include "proc.h"
#include "util.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

static const char *IPTABLES_CANDIDATES[] = {
    "/opt/sbin/iptables", "/usr/sbin/iptables", "/sbin/iptables", NULL
};
static const char *IP6TABLES_CANDIDATES[] = {
    "/opt/sbin/ip6tables", "/usr/sbin/ip6tables", "/sbin/ip6tables", NULL
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

/* Метка пишется с маской: младшая половина принадлежит другим
   программам, затирать её нельзя. */
static void mark_text(char *dst, unsigned size, unsigned mark)
{
    snprintf(dst, size, "0x%08x/0x%08x", mark, WL_MARK_MASK);
}

static void plan_family(rt_plan_t *p, const char *tables, const char *ipbin,
                        const char *ipflag, const wl_t *w, int v6, int remove)
{
    const char *table_arg = "mangle";

    if (!remove) {
        /* Своя цепочка — её можно чистить целиком, не трогая чужое. */
        const char *mk[] = { tables, "-t", table_arg, "-N", RT_CHAIN, NULL };
        add(p, 1, mk);
        const char *fl[] = { tables, "-t", table_arg, "-F", RT_CHAIN, NULL };
        add(p, 0, fl);
    }

    for (int i = 0; i < w->group_count; i++) {
        const wl_group_t *g = &w->groups[i];
        if (!g->iface[0]) continue;

        const char *set = v6 ? g->ipset6 : g->ipset4;

        char mark[32];
        mark_text(mark, sizeof(mark), g->mark);

        char table[16];
        snprintf(table, sizeof(table), "%u", g->table);

        if (!remove) {
            const char *rule[] = {
                tables, "-t", table_arg, "-A", RT_CHAIN,
                "-m", "set", "--match-set", set, "dst",
                "-j", "MARK", "--set-xmark", mark, NULL
            };
            add(p, 0, rule);
        }

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

    /* Врезку в PREROUTING всегда снимаем перед вставкой: так повторный
       вызов не плодит дубли, а снятие получается тем же кодом. */
    const char *unhook[] = {
        tables, "-t", table_arg, "-D", "PREROUTING", "-j", RT_CHAIN, NULL
    };
    add(p, 1, unhook);

    if (!remove) {
        const char *hook[] = {
            tables, "-t", table_arg, "-I", "PREROUTING", "1", "-j", RT_CHAIN, NULL
        };
        add(p, 0, hook);
    } else {
        const char *fl[] = { tables, "-t", table_arg, "-F", RT_CHAIN, NULL };
        add(p, 1, fl);
        const char *rm[] = { tables, "-t", table_arg, "-X", RT_CHAIN, NULL };
        add(p, 1, rm);
    }
}

static void plan_both(rt_plan_t *p, const rt_t *r, const wl_t *w, int remove)
{
    if (!p || !r || !w) return;
    memset(p, 0, sizeof(*p));

    plan_family(p, r->iptables, r->ip, "-4", w, 0, remove);
    if (r->ipv6 && r->ip6tables[0])
        plan_family(p, r->ip6tables, r->ip, "-6", w, 1, remove);
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

    for (int i = 0; i < p->count; i++) {
        const rt_cmd_t *c = &p->cmds[i];
        if (!c->argc) continue;

        char *argv[RT_ARGS_MAX + 1];
        char  copy[RT_ARGS_MAX][RT_ARG_LEN];

        for (int k = 0; k < c->argc; k++) {
            memcpy(copy[k], c->argv[k], RT_ARG_LEN);
            argv[k] = copy[k];
        }
        argv[c->argc] = NULL;

        char out[512];
        int  rc = proc_run(argv, out, sizeof(out), r->timeout);

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
