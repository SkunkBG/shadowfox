#include "status.h"
#include "engine.h"
#include "ipsets.h"
#include "proc.h"
#include "routing.h"
#include "shadowfox.h"
#include "log.h"
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
        "drop_empty=%lu\n"
        "drop_bad=%lu\n"
        "flushes=%lu\n"
        "restores=%lu\n"
        "rules=%d\n"
        "xray_pid=%ld\n"
        "xray_restarts=%d\n"
        "socks=%d\n"
        "sni_on=%d\n"
        "sni_seen=%lu\n"
        "sni_parsed=%lu\n"
        "sni_names=%lu\n"
        "sni_new=%lu\n"
        "sni_broken=%lu\n"
        "sni_bad=%lu\n"
        "dns_foreign=%lu\n"
        "sni_foreign=%lu\n"
        "sni_throttled=%lu\n"
        "sni_kept=%lu\n"
        "sni_reasm=%lu\n"
        "sni_partlost=%lu\n"
        "tunnel=%d\n"
        "tunnel_since=%ld\n"
        "tunnel_at=%ld\n"
        "tunnel_est=%d\n"
        "tunnel_pending=%d\n"
        "tunnel_why=%s\n"
        "tunnel_rtt=%d\n"
        "subs_urls=%d\n"
        "subs_ok=%d\n"
        "subs_cached=%d\n"
        "subs_at=%ld\n"
        "subs_host=%s\n"
        "subs_error=%s\n"
        "server_count=%d\n"
        "server_active=%s\n"
        "server_filter=%s\n",
        VERSION, (long)e->started_at,
        cfg->capture_iface, e->capturing, e->cap.filtered,
        e->cap.seen, e->cap.parsed, e->matched,
        e->cap.drop_notip, e->cap.drop_empty, e->cap.drop_bad,
        e->flushes, e->restores, e->rules_applied,
        (long)e->xray.pid, e->xray.restarts, cfg->socks_port,
        e->sniffing, e->sni.seen, e->sni.parsed,
        e->sni_names, e->sni_new, e->sni_broken, e->sni.drop_bad,
        e->cap.drop_foreign, e->sni.drop_foreign, e->sni_throttled,
        e->sni.partial_kept, e->sni.reassembled, e->sni.partial_lost,
        e->tunnel_state, (long)e->tunnel_since, (long)e->tunnel_sampled,
        e->tunnel_established, e->tunnel_pending, e->tunnel_why,
        e->tunnel_rtt_ms, e->subs_urls, e->subs_ok, e->subs_cached, (long)e->subs_at,
        e->subs_host, e->subs_error, e->server_count, e->server_active,
        e->server_filter);

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

/* Сколько записей в наборе.
   Возвращает число, либо IPSET_NO_SET если набора нет,
   либо IPSET_UNKNOWN если сосчитать не удалось.

   Различать это важно: раньше обе неудачи показывались как «набора
   нет», и отсутствие сведений выдавалось за отрицательный ответ. */
#define IPSET_NO_SET   (-1)
#define IPSET_UNKNOWN  (-2)

static long ipset_count(const char *bin, const char *set)
{
    char name[WL_SETNAME_MAX];
    char binbuf[128];
    char list[] = "list";

    str_copy(binbuf, sizeof(binbuf), bin);
    str_copy(name, sizeof(name), set);

    /* Полный список, а не краткий: в старых версиях ipset краткий режим
       не печатает число записей вовсе — проверено на роутере. */
    char *argv[] = { binbuf, list, name, NULL };

    static char out[128 * 1024];
    if (proc_run(argv, out, sizeof(out), 5) != 0) {
        /* Набора нет — ipset так и говорит. Всё прочее это наша беда. */
        return strstr(out, "does not exist") ? IPSET_NO_SET : IPSET_UNKNOWN;
    }

    /* Если новая версия сама посчитала — берём её число. */
    const char *n = strstr(out, "Number of entries:");
    if (n) return atol(n + 18);

    const char *m = strstr(out, "Members:");
    if (!m) return IPSET_UNKNOWN;

    long count = 0;
    for (const char *p = strchr(m, '\n'); p; p = strchr(p + 1, '\n'))
        if (p[1] && p[1] != '\n') count++;

    return count;
}

static void print_rule_counters(const rt_t *rt, const wl_t *w)
{
    unsigned long marked = 0, restored = 0;

    if (rt_counters(rt, w, &marked, &restored) != 0) {
        printf("  правила:    не прочитать\n");
        return;
    }

    if (marked == 0 && restored == 0) {
        /* Ноль сам по себе ещё не поломка: правило политики считает
           только новые соединения. Говорим ровно то, что знаем. */
        printf("  правила:    совпадений пока нет\n");
        return;
    }

    printf("  правила:    помечено соединений %lu, восстановлено пакетов %lu\n",
           marked, restored);
}

int status_print(const config_t *cfg)
{
    log_adopt_timezone();
    if (!cfg) return 1;

    char spath[CFG_PATH_MAX + 16];
    status_path(cfg, spath, sizeof(spath));

    printf("Shadow Fox %s\n\n", VERSION);

    int pid = pidfile_read_alive(cfg->pid_file);
    if (!pid) {
        printf("  служба:     не работает\n");
        printf("  запустить:  shadowfox start\n");
        return 1;
    }

    long started = status_num(spath, "started");
    if (started > 0) {
        long up = (long)time(NULL) - started;
        printf("  служба:     работает, pid %d, uptime %ldч %ldм\n",
               pid, up / 3600, (up % 3600) / 60);
    } else {
        printf("  служба:     работает, pid %d\n", pid);
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

        /* Ширину считаем в буквах, а не в байтах: "%-14s" ровняет по
           длине в байтах, и русские имена уезжают вдвое. */
        int width = 0;
        for (const char *c = g->name; *c; c++)
            if ((*c & 0xC0) != 0x80) width++;

        printf("    %s%*s -> %s", g->name,
               width < 14 ? 14 - width : 0, "",
               g->iface[0] ? g->iface : "(не задан)");
        if (g->target == WL_TARGET_IFACE)  printf(" (устройство)");
        if (g->target == WL_TARGET_POLICY) printf(" (политика)");
        if (!g->enabled) printf(" — ВЫКЛЮЧЕНА");
        printf("\n");

        /* У выключенной группы наборов нет по замыслу, и печатать
           «наборы ещё не созданы» значило бы намекать на поломку. */
        if (!g->enabled) continue;

    }

    /* Набор общий на цель: адреса печатаем по наборам, а не по группам,
       иначе одно и то же число повторялось бы семь раз. */
    if (have_ipset) {
        for (int i = 0; i < wl.group_count; i++) {
            const wl_group_t *g = &wl.groups[i];
            if (!g->enabled || !g->iface[0] || wl_set_owner(&wl, i) != i) continue;

            long c4 = ipset_count(ipbin, g->ipset4);
            long c6 = ipset_count(ipbin, g->ipset6);
            if (c4 == IPSET_NO_SET && c6 == IPSET_NO_SET)
                printf("    набор %s: ещё не создан\n", g->ipset4);
            else if (c4 == IPSET_UNKNOWN || c6 == IPSET_UNKNOWN)
                printf("    набор %s: есть, число записей не прочитать\n", g->ipset4);
            else
                printf("    набор %s: адресов v4 %ld, v6 %ld\n",
                       g->ipset4, c4 >= 0 ? c4 : 0, c6 >= 0 ? c6 : 0);
        }
    }
    printf("\n");

    if (status_num(spath, "started") < 0) {
        /* Файл пишется демоном при запуске и раз в минуту. Если его нет,
           демон, скорее всего, ещё не закончил старт. Сообщать в этом
           случае «перехват выключен» значит выдавать незнание за факт. */
        printf("  сведения от службы пока недоступны — она только что\n");
        printf("  запустилась. Повтори через несколько секунд.\n\n");

        rt_t rt0;
        rt_init(&rt0);
        if (rt_find_bins(&rt0)) print_rule_counters(&rt0, &wl);
        return 0;
    }

    if (status_num(spath, "subs_urls") > 0) {
        char host[SUBS_HOST_MAX] = "", serr[160] = "";
        status_get(spath, "subs_host", host, sizeof(host));
        status_get(spath, "subs_error", serr, sizeof(serr));
        long at = status_num(spath, "subs_at");
        char when[32] = "";
        if (at > 0) {
            time_t t = (time_t)at;
            strftime(when, sizeof(when), "%d.%m %H:%M", localtime(&t));
        }
        if (status_num(spath, "subs_ok") > 0)
            printf("  подписка:   %s, серверов %ld, загружена %s%s\n", host,
                   status_num(spath, "server_count"), when,
                   status_num(spath, "subs_cached") > 0 ? " (из кеша, сервер не ответил)" : "");
        else
            printf("  подписка:   %s НЕ ЗАГРУЖЕНА: %s\n", host, serr);
    }
    if (status_num(spath, "server_count") > 0) {
        char tag[128] = "", filt[64] = "";
        status_get(spath, "server_active", tag, sizeof(tag));
        status_get(spath, "server_filter", filt, sizeof(filt));
        printf("  сервер:     %s (в списке %ld%s%s)\n", tag, status_num(spath, "server_count"),
               filt[0] ? ", метка " : "", filt);
    }

    long xpid = status_num(spath, "xray_pid");
    if (xpid > 0) {
        printf("  своё ядро:  работает, pid %ld, socks порт %ld\n",
               xpid, status_num(spath, "socks"));
        long r = status_num(spath, "xray_restarts");
        if (r > 0) printf("              перезапусков: %ld\n", r);

        long tunnel = status_num(spath, "tunnel");
        long at     = status_num(spath, "tunnel_at");
        long since  = status_num(spath, "tunnel_since");
        long tnow   = (long)time(NULL);
        char why[192] = "";
        status_get(spath, "tunnel_why", why, sizeof(why));
        if (tunnel > 0) {
            long rtt = status_num(spath, "tunnel_rtt");
            printf("  туннель:    соединений с сервером %ld, срез %ld с назад%s%s\n",
                   status_num(spath, "tunnel_est"), at > 0 ? tnow - at : 0,
                   why[0] ? "\n              " : "", why);
            if (rtt >= 0)
                printf("              задержка до сервера %ld мс, по живым соединениям ядра\n", rtt);
        } else if (tunnel < 0) {
            char when[32] = "";
            if (since > 0) {
                time_t t = (time_t)since;
                strftime(when, sizeof(when), "%H:%M", localtime(&t));
            }
            printf("  туннель:    НЕ ОТВЕЧАЕТ с %s: %s\n", when, why);
            /* Самая частая причина по опыту — не провайдер, а сам сервер:
               его защита забанила адрес этой линии. Пока это не
               проверено, искать дальше бессмысленно. */
            printf("              с телефона по мобильной сети сервер открывается? Тогда адрес\n"
                   "              этой линии закрыт на самом сервере: бан fail2ban, антискана\n"
                   "              или Torrent-Blocker ноды. На сервере:\n"
                   "              nft list ruleset | grep -c <ваш внешний адрес>\n");
        } else {
            printf("  туннель:    соединений с сервером пока не было\n");
        }

        char last[200];
        long lines = 0;
        if (file_tail(XRAY_ERROR_LOG, last, sizeof(last), &lines) && lines > 0) {
            printf("              записей в журнале ядра: %ld (%s)\n", lines, XRAY_ERROR_LOG);
            printf("              последняя: %s\n", last);
        } else {
            printf("              записей в журнале ядра: нет\n");
        }
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
        /* «Без адресов» — не сбой: на каждое имя браузер спрашивает и
           AAAA, и часто получает пустой ответ. Сбой — только «битых». */
        long a = status_num(spath, "drop_notip");
        long b = status_num(spath, "drop_empty");
        long c = status_num(spath, "drop_bad");
        if (a > 0 || b > 0 || c > 0)
            printf("              мимо: не наш трафик %ld, без адресов %ld, "
                   "битых %ld\n", a, b, c);
    } else {
        printf("  перехват:   выключен\n");
    }

    if (status_num(spath, "sni_on") == 1) {
        printf("  перехват SNI: пакетов %ld, имён %ld, под правилами %ld\n",
               status_num(spath, "sni_seen"), status_num(spath, "sni_parsed"),
               status_num(spath, "sni_names"));

        /* Новых адресов мало при исправной работе: почти всё уже
           разложено через DNS. Ноль оборванных при ненулевых новых
           значит, что conntrack не сработал, и первые соединения
           уходят мимо туннеля. */
        printf("              новых адресов %ld, оборвано соединений %ld\n",
               status_num(spath, "sni_new"), status_num(spath, "sni_broken"));

        long bad = status_num(spath, "sni_bad");
        if (bad > 0)
            printf("              не разобрано ClientHello: %ld\n", bad);

        /* Приветствия, не поместившиеся в один сегмент. «Начато» заметно
           больше «склеено» — продолжения не доходят или не сходятся по
           номеру последовательности. */
        long kept = status_num(spath, "sni_kept");
        if (kept > 0)
            printf("              в двух сегментах: начато %ld, склеено %ld, потеряно %ld\n",
                   kept, status_num(spath, "sni_reasm"), status_num(spath, "sni_partlost"));

        /* Чужое — пакеты не роутеру и не от него: мост, широковещание,
           подделка. Придержанные обрывы при потоке — признак поддельных
           ClientHello. */
        long f1 = status_num(spath, "dns_foreign");
        long f2 = status_num(spath, "sni_foreign");
        long th = status_num(spath, "sni_throttled");
        if (f1 > 0 || f2 > 0 || th > 0)
            printf("              чужих пакетов: DNS %ld, SNI %ld; обрывов придержано %ld\n",
                   f1 > 0 ? f1 : 0, f2 > 0 ? f2 : 0, th > 0 ? th : 0);
    } else {
        printf("  перехват SNI: выключен\n");
    }

    long restores = status_num(spath, "restores");
    if (restores > 0)
        printf("  восстановлений правил: %ld\n", restores);

    printf("\n");

    rt_t rt;
    rt_init(&rt);
    if (rt_find_bins(&rt)) print_rule_counters(&rt, &wl);

    return 0;
}
