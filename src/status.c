#include "status.h"
#include "engine.h"
#include "ipsets.h"
#include "proc.h"
#include "routing.h"
#include "shadowfox.h"
#include "util.h"
#include "watchlist.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

void status_path(const config_t *cfg, char *dst, unsigned dst_size)
{
    if (!dst || !dst_size) return;
    dst[0] = '\0';
    if (!cfg || !cfg->pid_file[0]) return;

    char base[CFG_PATH_MAX];
    str_copy(base, sizeof(base), cfg->pid_file);

    /* Отрезаем расширение pid-файла и ставим своё. */
    char *dot   = strrchr(base, '.');
    char *slash = strrchr(base, '/');
    if (dot && (!slash || dot > slash)) *dot = '\0';

    snprintf(dst, dst_size, "%s.status", base);
}

void status_write(const struct engine *ce, const config_t *cfg)
{
    const engine_t *e = (const engine_t *)ce;
    if (!e || !cfg) return;

    char path[CFG_PATH_MAX + 16];
    status_path(cfg, path, sizeof(path));
    if (!path[0]) return;

    char tmp[CFG_PATH_MAX + 32];
    snprintf(tmp, sizeof(tmp), "%s.new", path);

    FILE *f = fopen(tmp, "w");
    if (!f) return;

    fprintf(f,
        "version=%s\n"
        "started=%ld\n"
        "capture_iface=%s\n"
        "capture_on=%d\n"
        "capture_filtered=%d\n"
        "seen=%lu\n"
        "parsed=%lu\n"
        "matched=%lu\n"
        "drop_notip=%lu\n"
        "drop_notreply=%lu\n"
        "flushes=%lu\n"
        "restores=%lu\n"
        "rules=%d\n"
        "xray_pid=%ld\n"
        "xray_restarts=%d\n"
        "socks=%d\n",
        VERSION, (long)e->started_at,
        cfg->capture_iface, e->capturing, e->cap.filtered,
        e->cap.seen, e->cap.parsed, e->matched,
        e->cap.drop_notip, e->cap.drop_notreply,
        e->flushes, e->restores, e->rules_applied,
        (long)e->xray.pid, e->xray.restarts, cfg->socks_port);

    fclose(f);
    rename(tmp, path);
}

/* Читает значение ключа из файла состояния. */
static int status_get(const char *path, const char *key, char *out, size_t size)
{
    if (out && size) out[0] = '\0';

    FILE *f = fopen(path, "r");
    if (!f) return 0;

    char   line[256];
    size_t klen  = strlen(key);
    int    found = 0;

    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, key, klen) != 0 || line[klen] != '=') continue;
        char *v = str_trim(line + klen + 1);
        str_copy(out, size, v);
        found = 1;
        break;
    }

    fclose(f);
    return found;
}

static long status_num(const char *path, const char *key)
{
    char v[64];
    if (!status_get(path, key, v, sizeof(v))) return -1;
    return atol(v);
}

/* Сколько записей в наборе. -1, если набора нет. */
static long ipset_count(const char *bin, const char *set)
{
    char  name[WL_SETNAME_MAX];
    char  flag[] = "-t";
    char  list[] = "list";
    char  binbuf[128];

    str_copy(binbuf, sizeof(binbuf), bin);
    str_copy(name, sizeof(name), set);

    char *argv[] = { binbuf, list, flag, name, NULL };
    char  out[2048];

    if (proc_run(argv, out, sizeof(out), 5) != 0) return -1;

    const char *p = strstr(out, "Number of entries:");
    if (!p) return -1;
    return atol(p + 18);
}

static void print_rule_counters(const rt_t *rt)
{
    char binbuf[RT_BIN_MAX];
    str_copy(binbuf, sizeof(binbuf), rt->iptables);

    char t[] = "-t", mangle[] = "mangle", L[] = "-L";
    char chain[] = RT_CHAIN, v[] = "-v", n[] = "-n", x[] = "-x";

    char *argv[] = { binbuf, t, mangle, L, chain, v, n, x, NULL };
    char  out[4096];

    if (proc_run(argv, out, sizeof(out), 5) != 0) {
        printf("  правила:    цепочки нет\n");
        return;
    }

    /* Первые числа в строках правил — пакеты и байты. */
    long marked = -1, restored = -1;
    const char *line = out;
    while ((line = strchr(line, '\n')) != NULL) {
        line++;
        long pkts = 0;
        if (sscanf(line, " %ld", &pkts) != 1) continue;
        if (strstr(line, "CONNMARK set") || strstr(line, "MARK set")) marked = pkts;
        else if (strstr(line, "restore"))                            restored = pkts;
    }

    if (marked >= 0)
        printf("  правила:    помечено соединений %ld, восстановлено пакетов %ld\n",
               marked, restored >= 0 ? restored : 0);
    else
        printf("  правила:    цепочка есть, совпадений пока нет\n");
}

int status_print(const config_t *cfg)
{
    if (!cfg) return 1;

    char spath[CFG_PATH_MAX + 16];
    status_path(cfg, spath, sizeof(spath));

    printf("Shadow Fox %s\n\n", VERSION);

    int pid = pidfile_read_alive(cfg->pid_file);
    if (!pid) {
        printf("  демон:      не работает\n");
        printf("  запустить:  shadowfox start\n");
        return 1;
    }

    long started = status_num(spath, "started");
    if (started > 0) {
        long up = (long)time(NULL) - started;
        printf("  демон:      работает, pid %d, uptime %ldч %ldм\n",
               pid, up / 3600, (up % 3600) / 60);
    } else {
        printf("  демон:      работает, pid %d\n", pid);
    }
    printf("  конфиг:     %s\n\n", cfg->conf_file);

    /* Списки читаем заново: так видно, что лежит на диске сейчас,
       а не что демон прочитал при старте. */
    static wl_t wl;
    wl_init(&wl);

    char dpath[CFG_PATH_MAX + 32], ipath[CFG_PATH_MAX + 32];
    snprintf(dpath, sizeof(dpath), "%s/domain.conf", cfg->conf_dir);
    snprintf(ipath, sizeof(ipath), "%s/ip.list", cfg->conf_dir);
    wl_load_domains(&wl, dpath);
    wl_load_cidrs(&wl, ipath);
    wl_classify_targets(&wl, NULL);

    printf("  списки:     групп %d, доменов %d, подсетей %d",
           wl.group_count, wl.domain_count, wl.cidr_count);
    if (wl.skipped) printf(", пропущено строк %d", wl.skipped);
    printf("\n");

    char ipbin[128];
    int  have_ipset = ips_find_bin(ipbin, sizeof(ipbin));

    for (int i = 0; i < wl.group_count; i++) {
        const wl_group_t *g = &wl.groups[i];
        printf("    %-14s -> %s", g->name, g->iface[0] ? g->iface : "(не задан)");
        if (g->target == WL_TARGET_IFACE)  printf(" (устройство)");
        if (g->target == WL_TARGET_POLICY) printf(" (политика)");
        printf("\n");

        if (have_ipset) {
            long c4 = ipset_count(ipbin, g->ipset4);
            long c6 = ipset_count(ipbin, g->ipset6);
            printf("        наборы: %s %s, %s %s\n",
                   g->ipset4, c4 >= 0 ? "" : "нет",
                   g->ipset6, c6 >= 0 ? "" : "нет");
            if (c4 >= 0) printf("        адресов: v4 %ld, v6 %ld\n", c4, c6 >= 0 ? c6 : 0);
        }
    }
    printf("\n");

    long xpid = status_num(spath, "xray_pid");
    if (xpid > 0) {
        printf("  своё ядро:  работает, pid %ld, socks порт %ld\n",
               xpid, status_num(spath, "socks"));
        long r = status_num(spath, "xray_restarts");
        if (r > 0) printf("              перезапусков: %ld\n", r);
    } else {
        printf("  своё ядро:  не запущено (нет %s?)\n", cfg->nodes_file);
    }

    char iface[64] = "";
    status_get(spath, "capture_iface", iface, sizeof(iface));
    if (status_num(spath, "capture_on") == 1) {
        printf("  перехват:   %s%s\n", iface,
               status_num(spath, "capture_filtered") == 1
                   ? "" : ", без фильтра ядра");
        printf("              пакетов %ld, ответов %ld, адресов %ld\n",
               status_num(spath, "seen"), status_num(spath, "parsed"),
               status_num(spath, "matched"));
        long a = status_num(spath, "drop_notip");
        long b = status_num(spath, "drop_notreply");
        if (a > 0 || b > 0)
            printf("              мимо: не UDP/53 %ld, не разобрались %ld\n", a, b);
    } else {
        printf("  перехват:   выключен\n");
    }

    long restores = status_num(spath, "restores");
    if (restores > 0)
        printf("  восстановлений правил: %ld\n", restores);

    printf("\n");

    rt_t rt;
    rt_init(&rt);
    if (rt_find_bins(&rt)) print_rule_counters(&rt);

    return 0;
}
