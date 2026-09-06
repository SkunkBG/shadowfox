#include "ipsets.h"
#include "log.h"
#include "proc.h"
#include "util.h"

#include <arpa/inet.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static const char *IPSET_CANDIDATES[] = {
    "/opt/sbin/ipset",
    "/usr/sbin/ipset",
    "/sbin/ipset",
    NULL
};

void ips_init(ips_t *s, const char *bin)
{
    memset(s, 0, sizeof(*s));
    s->timeout = 15;
    if (bin && *bin) str_copy(s->bin, sizeof(s->bin), bin);
    else             ips_find_bin(s->bin, sizeof(s->bin));
}

int ips_find_bin(char *dst, unsigned dst_size)
{
    if (!dst || !dst_size) return 0;
    dst[0] = '\0';

    for (int i = 0; IPSET_CANDIDATES[i]; i++) {
        if (access(IPSET_CANDIDATES[i], X_OK) == 0) {
            str_copy(dst, dst_size, IPSET_CANDIDATES[i]);
            return 1;
        }
    }
    return 0;
}

const char *ips_pending(const ips_t *s)
{
    return s ? s->batch : "";
}

static void queue(ips_t *s, const char *fmt, ...)
{
    if (!s) return;

    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(s->batch + s->used, sizeof(s->batch) - s->used, fmt, ap);
    va_end(ap);

    if (n < 0 || (unsigned)n >= sizeof(s->batch) - s->used) {
        /* Не влезло — обрезаем до последней целой строки и считаем потерю.
           Молча оборванная команда была бы хуже: ipset restore отверг бы
           всю пачку целиком. */
        s->batch[s->used] = '\0';
        s->overflows++;
        return;
    }

    s->used += (unsigned)n;
    s->queued++;
}

void ips_queue_create(ips_t *s, const wl_t *w, int timeout)
{
    if (!s || !w) return;

    char tmo[32] = "";
    if (timeout > 0) snprintf(tmo, sizeof(tmo), " timeout %d", timeout);

    for (int i = 0; i < w->group_count; i++) {
        /* -exist делает создание идемпотентным: после перезапуска демона
           наборы уже есть, и это нормальная ситуация, а не ошибка. */
        queue(s, "create %s hash:net family inet%s -exist\n",
              w->groups[i].ipset4, tmo);
        queue(s, "create %s hash:net family inet6%s -exist\n",
              w->groups[i].ipset6, tmo);
    }
}

void ips_destroy(ips_t *s, const wl_t *w)
{
    if (!s || !w || !s->bin[0]) return;

    for (int i = 0; i < w->group_count; i++) {
        for (int v = 0; v < 2; v++) {
            char bin[IPS_BIN_MAX];
            char cmd[]  = "destroy";
            char name[WL_SETNAME_MAX];

            str_copy(bin, sizeof(bin), s->bin);
            str_copy(name, sizeof(name),
                     v ? w->groups[i].ipset6 : w->groups[i].ipset4);

            char *argv[] = { bin, cmd, name, NULL };
            char  out[256];

            /* Отсутствие набора и ссылки на него из правил — обе
               ситуации штатные, ругаться не на что. */
            proc_run(argv, out, sizeof(out), s->timeout);
        }
    }
}

/* Наборы групп, которых больше нет. Группу переименовали или удалили —
   её наборы оставались висеть в ядре: занимали память и путали
   диагностику, потому что «ipset list» показывал давно неживое.
   Вызывать можно только когда правила уже сняты: набор, на который
   ссылается правило, ядро удалить не даст. */
int ips_destroy_orphans(ips_t *s, const wl_t *w)
{
    if (!s || !w || !s->bin[0]) return 0;

    char bin[IPS_BIN_MAX];
    char arg1[] = "list";
    char arg2[] = "-n";
    str_copy(bin, sizeof(bin), s->bin);

    char *argv[] = { bin, arg1, arg2, NULL };
    static char out[16 * 1024];

    if (proc_run(argv, out, sizeof(out), s->timeout) != 0) return 0;

    int killed = 0;

    for (char *line = strtok(out, "\n"); line; line = strtok(NULL, "\n")) {
        char *name = str_trim(line);

        if (strncmp(name, "sf4_", 4) != 0 && strncmp(name, "sf6_", 4) != 0)
            continue;

        int ours = 0;
        for (int i = 0; i < w->group_count && !ours; i++)
            ours = !strcmp(name, w->groups[i].ipset4) ||
                   !strcmp(name, w->groups[i].ipset6);
        if (ours) continue;

        char nbin[IPS_BIN_MAX];
        char cmd[] = "destroy";
        char nm[WL_SETNAME_MAX];
        str_copy(nbin, sizeof(nbin), s->bin);
        if (str_copy(nm, sizeof(nm), name) != 0) continue;

        char *dargv[] = { nbin, cmd, nm, NULL };
        char  derr[256];
        if (proc_run(dargv, derr, sizeof(derr), s->timeout) == 0) killed++;
    }

    return killed;
}

void ips_queue_add(ips_t *s, const wl_t *w, int group, int family,
                   const char *text)
{
    if (!s || !w || !text || !*text) return;
    if (group < 0 || group >= w->group_count) return;
    if (family != 4 && family != 6) return;

    const char *set = (family == 4) ? w->groups[group].ipset4
                                    : w->groups[group].ipset6;
    queue(s, "add %s %s -exist\n", set, text);
}

void ips_queue_cidrs(ips_t *s, const wl_t *w)
{
    if (!s || !w) return;

    for (int i = 0; i < w->cidr_count; i++) {
        const wl_cidr_t *c = &w->cidrs[i];
        if (c->group >= w->group_count) continue;

        char text[64];
        if (!inet_ntop_prefix(c, text, sizeof(text))) continue;

        const char *set = (c->family == 4) ? w->groups[c->group].ipset4
                                           : w->groups[c->group].ipset6;
        queue(s, "add %s %s -exist\n", set, text);
    }
}

int ips_flush(ips_t *s, char *err, unsigned err_size)
{
    if (!s) return -1;
    if (!s->used) return 0;

    if (!s->bin[0]) {
        if (err && err_size) str_copy(err, err_size, "не найден ipset");
        return -1;
    }

    char bin[IPS_BIN_MAX];
    str_copy(bin, sizeof(bin), s->bin);

    char  out[1024];
    char *argv[] = { bin, "restore", "-exist", NULL };
    int   rc     = proc_run_input(argv, s->batch, out, sizeof(out), s->timeout);

    unsigned sent = s->queued;

    /* Очередь сбрасываем в любом случае: копить команды, которые ipset
       уже отверг, значит отвергать и все следующие пачки. */
    s->batch[0] = '\0';
    s->used     = 0;
    s->queued   = 0;

    if (rc != 0) {
        if (err && err_size)
            snprintf(err, err_size, "ipset restore вернул %d: %s", rc, out);
        return -1;
    }

    s->applied += sent;
    return 0;
}
