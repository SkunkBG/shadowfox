#include "ipsets.h"
#include "log.h"
#include "proc.h"
#include "util.h"

#include <arpa/inet.h>
#include <stdarg.h>
#include <stdlib.h>
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
        /* Выключенной группе набор не нужен: правил на неё нет, а лишний
           набор потом уберёт уборка сирот. */
        if (!w->groups[i].enabled) continue;
        /* Набор общий на цель — создаём один раз. */
        if (wl_set_owner(w, i) != i) continue;

        /* -exist делает создание идемпотентным: после перезапуска демона
           наборы уже есть, и это нормальная ситуация, а не ошибка.
           maxelem как у HydraRoute: 65536 TikTok с YouTube за неделю
           выбирали. */
        queue(s, "create %s hash:net family inet maxelem 262144%s -exist\n",
              w->groups[i].ipset4, tmo);
        queue(s, "create %s hash:net family inet6 maxelem 262144%s -exist\n",
              w->groups[i].ipset6, tmo);
    }
}

void ips_destroy(ips_t *s, const wl_t *w)
{
    if (!s || !w || !s->bin[0]) return;

    for (int i = 0; i < w->group_count; i++) {
        if (wl_set_owner(w, i) != i) continue;
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

        /* Выключенная группа своим набором не считается: его и надо
           убрать, чтобы в ядре не оставалось того, чего нет в правилах. */
        int ours = 0;
        for (int i = 0; i < w->group_count && !ours; i++)
            ours = w->groups[i].enabled &&
                   (!strcmp(name, w->groups[i].ipset4) ||
                    !strcmp(name, w->groups[i].ipset6));
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

/* Разбор `ipset list -t`: у каждого набора идёт строка Name, следом
   Header с параметрами. Нас интересует только timeout — остальное у
   набора менять не приходится. */
int ips_headers_differ(const char *text, const wl_t *w, int timeout)
{
    if (!text || !w) return 1;

    char name[WL_SETNAME_MAX] = "";

    const char *line = text;
    for (;;) {
        const char *nl  = strchr(line, '\n');
        size_t      len = nl ? (size_t)(nl - line) : strlen(line);

        if (len > 6 && !strncmp(line, "Name: ", 6)) {
            size_t n = len - 6;
            if (n >= sizeof(name)) n = sizeof(name) - 1;
            memcpy(name, line + 6, n);
            name[n] = '\0';
        } else if (len > 8 && !strncmp(line, "Header: ", 8) && name[0]) {
            /* Наш ли это набор. Чужие в глаза не смотрим. */
            int ours = 0;
            for (int i = 0; i < w->group_count && !ours; i++) {
                if (!strcmp(name, w->groups[i].ipset4)) ours = 1;
                if (!strcmp(name, w->groups[i].ipset6)) ours = 1;
            }

            if (ours) {
                int have = 0;
                const char *t = memmem(line, len, "timeout ", 8);
                if (t) have = atoi(t + 8);
                if (have != timeout) return 1;
            }
            name[0] = '\0';
        }

        if (!nl) break;
        line = nl + 1;
    }

    return 0;
}

int ips_timeout_differs(ips_t *s, const wl_t *w, int timeout)
{
    if (!s || !w || !s->bin[0]) return 1;

    char binbuf[IPS_BIN_MAX];
    str_copy(binbuf, sizeof(binbuf), s->bin);

    char list[] = "list", terse[] = "-t";
    char *argv[] = { binbuf, list, terse, NULL };

    static char out[32768];
    int trunc = 0;
    if (proc_run_capture(argv, out, sizeof(out), 10, &trunc) != 0) return 1;

    /* Обрезанный вывод — неясность, а при неясности пересоздаём: наши
       наборы могли остаться за срезом, и «расхождения нет» было бы
       ответом по тексту, которого мы не видели. */
    if (trunc) return 1;

    return ips_headers_differ(out, w, timeout);
}

void ips_entry_counts(const char *text, const wl_t *w, long *c4, long *c6)
{
    if (!w) return;
    for (int i = 0; i < w->group_count; i++) { c4[i] = -1; c6[i] = -1; }
    if (!text) return;

    char  name[WL_SETNAME_MAX] = "";
    const char *line = text;
    for (;;) {
        const char *nl  = strchr(line, '\n');
        size_t      len = nl ? (size_t)(nl - line) : strlen(line);

        if (len > 6 && !strncmp(line, "Name: ", 6)) {
            size_t n = len - 6;
            if (n >= sizeof(name)) n = sizeof(name) - 1;
            memcpy(name, line + 6, n);
            name[n] = '\0';
        } else if (len > 19 && !strncmp(line, "Number of entries: ", 19) && name[0]) {
            long cnt = atol(line + 19);
            for (int i = 0; i < w->group_count; i++) {
                if (!strcmp(name, w->groups[i].ipset4)) c4[i] = cnt;
                if (!strcmp(name, w->groups[i].ipset6)) c6[i] = cnt;
            }
            name[0] = '\0';
        }

        if (!nl) break;
        line = nl + 1;
    }
}

int ips_count_entries(ips_t *s, const wl_t *w, long *c4, long *c6)
{
    if (!s || !w || !s->bin[0]) return -1;

    char binbuf[IPS_BIN_MAX];
    str_copy(binbuf, sizeof(binbuf), s->bin);
    char list[] = "list", terse[] = "-t";
    char *argv[] = { binbuf, list, terse, NULL };

    static char out[32768];
    int trunc = 0;
    if (proc_run_capture(argv, out, sizeof(out), 10, &trunc) != 0) return -1;

    ips_entry_counts(out, w, c4, c6);
    return 0;
}

void ips_members_parse(const char *text, const wl_t *w,
                       void (*cb)(int, int, const char *, long, void *), void *ctx)
{
    if (!text || !w || !cb) return;

    int group = -1, family = 0, in_members = 0;
    const char *line = text;
    for (;;) {
        const char *nl  = strchr(line, '\n');
        size_t      len = nl ? (size_t)(nl - line) : strlen(line);

        if (len > 6 && !strncmp(line, "Name: ", 6)) {
            char name[WL_SETNAME_MAX];
            size_t n = len - 6;
            if (n >= sizeof(name)) n = sizeof(name) - 1;
            memcpy(name, line + 6, n);
            name[n] = '\0';
            group = -1; family = 0; in_members = 0;
            for (int i = 0; i < w->group_count; i++) {
                if (!strcmp(name, w->groups[i].ipset4)) { group = i; family = 4; }
                if (!strcmp(name, w->groups[i].ipset6)) { group = i; family = 6; }
            }
        } else if (len == 8 && !strncmp(line, "Members:", 8)) {
            in_members = group >= 0;
        } else if (in_members && len > 0 && group >= 0) {
            char entry[128];
            size_t n = len < sizeof(entry) - 1 ? len : sizeof(entry) - 1;
            memcpy(entry, line, n);
            entry[n] = '\0';

            char *sp = strchr(entry, ' ');
            long  remaining = -1;
            if (sp) {
                *sp = '\0';
                const char *t = strstr(sp + 1, "timeout ");
                if (t) remaining = atol(t + 8);
            }
            if (!strchr(entry, '/')) cb(group, family, entry, remaining, ctx);
        } else if (len == 0) {
            in_members = 0;
        }

        if (!nl) break;
        line = nl + 1;
    }
}

int ips_list_members(ips_t *s, const wl_t *w,
                     void (*cb)(int, int, const char *, long, void *), void *ctx)
{
    if (!s || !w || !s->bin[0]) return -1;

    char binbuf[IPS_BIN_MAX];
    str_copy(binbuf, sizeof(binbuf), s->bin);
    char list[] = "list";
    char *argv[] = { binbuf, list, NULL };

    /* Тысячи записей по ~30 байт: TikTok один даёт полторы тысячи. */
    static char out[1024 * 1024];
    int trunc = 0;
    if (proc_run_capture(argv, out, sizeof(out), 15, &trunc) != 0) return -1;

    ips_members_parse(out, w, cb, ctx);
    return trunc ? -1 : 0;
}
