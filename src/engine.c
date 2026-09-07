#include "shadowfox.h"
#include "engine.h"
#include "apply.h"
#include "log.h"
#include "status.h"
#include "nodelist.h"
#include "xraycfg.h"
#include "proc.h"
#include "util.h"

#include <stdio.h>

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

/* Как часто отдавать накопленные адреса в ipset. Раз в секунду: адреса
   должны попадать в наборы быстро, иначе первое соединение к домену
   уйдёт мимо туннеля, а пачками — чтобы не порождать процесс на каждый
   ответ. */
#define ENGINE_FLUSH_SECONDS 1

/* Пауза перед восстановлением правил. Наши собственные правки netfilter
   поднимают ndm-хуки роутера, а те присылают SIGUSR1 — за одну секунду
   их приходило пять подряд. Пауза схлопывает всплеск в одно применение
   и разрывает цепную реакцию. */
#define ENGINE_RESTORE_DELAY 2
#define ENGINE_BREAK_BUDGET  20   /* обрывов соединений в секунду */

/* Расписание проверки туннеля. Живой проверяем раз в минуту, упавший —
   чаще, чтобы восстановление заметить без долгой ложной тревоги. */
#define ENGINE_PROBE_FIRST 5
#define ENGINE_PROBE_OK    60
#define ENGINE_PROBE_FAIL  20

void engine_init(engine_t *e)
{
    memset(e, 0, sizeof(*e));
    wl_init(&e->wl);
    ips_init(&e->ips, NULL);
    rt_init(&e->rt);
    dcap_init(&e->cap);
    scap_init(&e->sni);
    rci_init(&e->rci);
    sv_init(&e->xray, "", "");
    probe_init(&e->probe);
}

int engine_fds(const engine_t *e, int *out, int max)
{
    if (!e || !out || max <= 0) return 0;

    int n = 0;
    if (e->capturing && n < max) out[n++] = e->cap.fd;
    if (e->sniffing  && n < max) out[n++] = e->sni.fd;
    int pfd = probe_fd(&e->probe);
    if (pfd >= 0 && n < max) out[n++] = pfd;
    return n;
}

/* Помним, что адрес уже разложен по набору. Возвращает 1, если увидели
   его впервые.

   Срок жизни записи привязан к сроку жизни записи в самом наборе: как
   только адрес оттуда состарится, помнить о нём нам тоже незачем. */
static int note_addr(engine_t *e, int group, int family,
                     const unsigned char *addr, time_t now)
{
    size_t alen = (family == 4) ? 4 : 16;
    time_t ttl  = e->ipset_timeout > 0 ? e->ipset_timeout : 86400;

    int oldest = 0;
    for (int i = 0; i < e->known_count; i++) {
        if (e->known[i].family == family && e->known[i].group == group &&
            memcmp(e->known[i].addr, addr, alen) == 0) {
            if (now - e->known[i].at <= ttl) {
                e->known[i].at = now;
                return 0;
            }
            /* Состарилась — переиспользуем как новую. */
            e->known[i].at = now;
            return 1;
        }
        if (e->known[i].at < e->known[oldest].at) oldest = i;
    }

    int slot;
    if (e->known_count < ENG_KNOWN_MAX) slot = e->known_count++;
    else                                slot = oldest;

    memset(e->known[slot].addr, 0, sizeof(e->known[slot].addr));
    memcpy(e->known[slot].addr, addr, alen);
    e->known[slot].family = (unsigned char)family;
    e->known[slot].group  = (short)group;
    e->known[slot].at     = now;
    return 1;
}

/* Пойманный ответ: раскладываем адреса по группам. */
static void on_reply(const dns_reply_t *r, void *ctx)
{
    engine_t *e       = ctx;
    int       matched = 0;

    for (int i = 0; i < r->answer_count; i++) {
        const dns_answer_t *a = &r->answers[i];

        /* Сначала по владельцу записи, потом по исходному вопросу: при
           цепочке CNAME правило может быть написано на любое из имён. */
        int group = wl_match_domain(&e->wl, a->name);
        if (group < 0) group = wl_match_domain(&e->wl, r->question);
        if (group < 0) continue;

        char text[INET6_ADDRSTRLEN];
        int  af = (a->family == 4) ? AF_INET : AF_INET6;
        if (!inet_ntop(af, a->addr, text, sizeof(text))) continue;

        ips_queue_add(&e->ips, &e->wl, group, a->family, text);
        note_addr(e, group, a->family, a->addr, time(NULL));
        e->matched++;
        matched++;

        log_debug("%s -> %s в группу %s", r->question, text,
                  e->wl.groups[group].name);
    }

    /* Имя, не попавшее ни в один список, тоже полезно видеть: когда
       совпадений нет вовсе, только так и понять, какие домены вообще
       приходят и на чём именно расходится сопоставление. */
    if (!matched)
        log_debug("мимо списков: %s (%d адрес(ов))",
                  r->question, r->answer_count);
}

/* Обрыв соединения, которое уже установилось мимо туннеля.

   Без него первое обращение к каждому новому адресу уходит напрямую
   целиком: адрес мы кладём в набор, но у этого соединения метка уже не
   поставится — она ставится только на новом. Убрав запись conntrack, мы
   заставляем приложение переустановить соединение, и оно с самого
   начала идёт по политике.

   conntrack ставится зависимостью пакета. Если его всё же нет или ядро
   без nf_conntrack_netlink, перехват продолжает работать: просто первое
   соединение к новому адресу утекает, остальные идут верно. Молчать об
   этом нельзя — предупреждаем один раз. */
static void break_conn(engine_t *e, const sni_hit_t *h,
                       const char *src, const char *dst)
{
    static const char *CT_CANDIDATES[] = {
        "/opt/sbin/conntrack", "/opt/bin/conntrack",
        "/usr/sbin/conntrack", "/sbin/conntrack", NULL
    };

    if (!e->ct_checked) {
        e->ct_checked = 1;
        for (int i = 0; CT_CANDIDATES[i]; i++) {
            if (access(CT_CANDIDATES[i], X_OK) == 0) {
                str_copy(e->ct_bin, sizeof(e->ct_bin), CT_CANDIDATES[i]);
                break;
            }
        }
    }

    if (!e->ct_bin[0]) {
        if (!e->ct_warned) {
            e->ct_warned = 1;
            log_warn("нет conntrack: первое соединение к каждому новому "
                     "адресу пойдёт мимо туннеля. Поставь пакет conntrack");
        }
        return;
    }

    /* 16, хотя порт не длиннее пяти цифр: компилятор считает %u по
       максимуму типа, и в восемь байт это по его меркам не влезает. */
    char sp[16], dp[16], fam[8];
    snprintf(sp, sizeof(sp), "%u", h->sport);
    snprintf(dp, sizeof(dp), "%u", h->dport);
    str_copy(fam, sizeof(fam), h->family == 4 ? "ipv4" : "ipv6");

    char bin[128], a_d[] = "-D", a_f[] = "-f", a_p[] = "-p", tcp[] = "tcp";
    char a_s[] = "-s", a_dd[] = "-d", a_sp[] = "--sport", a_dp[] = "--dport";
    char srcbuf[INET6_ADDRSTRLEN], dstbuf[INET6_ADDRSTRLEN];

    str_copy(bin, sizeof(bin), e->ct_bin);
    str_copy(srcbuf, sizeof(srcbuf), src);
    str_copy(dstbuf, sizeof(dstbuf), dst);

    char *argv[] = { bin, a_d, a_f, fam, a_p, tcp,
                     a_s, srcbuf, a_dd, dstbuf,
                     a_sp, sp, a_dp, dp, NULL };
    char out[256] = "";

    int rc = proc_run(argv, out, sizeof(out), 5);

    /* Ненулевой код тут обычен: запись могла закрыться сама, пока мы
       разбирали пакет. Это не сбой, поэтому не шумим. */
    if (rc == 0) e->sni_broken++;

    log_debug("conntrack -D %s %s:%s -> %s:%s = %d",
              fam, srcbuf, sp, dstbuf, dp, rc);
}

/* Пойманное в ClientHello имя. В отличие от DNS адрес тут не
   предполагаемый, а тот самый, к которому клиент уже пошёл. */
static void on_sni(const sni_hit_t *h, void *ctx)
{
    engine_t *e = ctx;

    int group = wl_match_domain(&e->wl, h->name);
    if (group < 0) {
        log_debug("SNI мимо списков: %s", h->name);
        return;
    }

    e->sni_names++;

    char dst[INET6_ADDRSTRLEN], src[INET6_ADDRSTRLEN];
    int  af = (h->family == 4) ? AF_INET : AF_INET6;
    if (!inet_ntop(af, h->dst, dst, sizeof(dst))) return;
    if (!inet_ntop(af, h->src, src, sizeof(src))) return;

    /* Адрес уже разложен — значит это соединение и так пойдёт куда
       надо. Рвать его нельзя: так мы обрывали бы каждое соединение к
       уже настроенному сайту, по кругу. */
    if (!note_addr(e, group, h->family, h->dst, time(NULL))) return;

    e->sni_new++;
    ips_queue_add(&e->ips, &e->wl, group, h->family, dst);

    log_info("SNI %s -> %s в группу %s", h->name, dst, e->wl.groups[group].name);

    /* Бюджет обрывов. Обрыв делается по 5-tuple из пакета, а пакет в
       сети может подделать кто угодно — это единственное место, где
       чужое устройство командует нашим conntrack. Адрес в набор всё
       равно кладём (следующее соединение пойдёт верно), а рвать больше
       ENGINE_BREAK_BUDGET в секунду не станем: настоящему трафику
       столько новых адресов в секунду не нужно. */
    time_t now = time(NULL);
    if (now != e->break_sec) { e->break_sec = now; e->break_in_sec = 0; }
    if (++e->break_in_sec > ENGINE_BREAK_BUDGET) {
        e->sni_throttled++;
        if (e->break_in_sec == ENGINE_BREAK_BUDGET + 1)
            log_warn("обрывов больше %d в секунду — похоже на подделку "
                     "ClientHello, лишние не делаю", ENGINE_BREAK_BUDGET);
        return;
    }

    /* Не рвём здесь: сначала весь проход, один сброс набора, потом
       обрывы — см. flush_pending_breaks. */
    if (e->pending_count < ENG_PENDING_MAX) {
        int k = e->pending_count++;
        e->pending[k].family = h->family;
        memcpy(e->pending[k].src, h->src, 16);
        memcpy(e->pending[k].dst, h->dst, 16);
        e->pending[k].sport = h->sport;
        e->pending[k].dport = h->dport;
    } else {
        e->pending_lost++;
    }
}

/* После прохода по пакетам: один ipset restore на всё накопленное,
   и только потом обрывы. Порядок важен: приложение переустановит
   соединение через доли секунды, и адрес к этому моменту обязан быть
   в наборе, иначе метки снова не будет. */
static void flush_pending_breaks(engine_t *e)
{
    if (!e->pending_count) return;

    char err[160] = "";
    if (ips_flush(&e->ips, err, sizeof(err)) != 0) {
        log_warn("ipset после SNI: %s", err);
    } else {
        e->flushes++;
        for (int i = 0; i < e->pending_count; i++) {
            sni_hit_t h;
            memset(&h, 0, sizeof(h));
            h.family = e->pending[i].family;
            memcpy(h.src, e->pending[i].src, 16);
            memcpy(h.dst, e->pending[i].dst, 16);
            h.sport = e->pending[i].sport;
            h.dport = e->pending[i].dport;

            char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
            int  af = (h.family == 4) ? AF_INET : AF_INET6;
            if (!inet_ntop(af, h.src, src, sizeof(src))) continue;
            if (!inet_ntop(af, h.dst, dst, sizeof(dst))) continue;
            break_conn(e, &h, src, dst);
        }
    }

    if (e->pending_lost) {
        log_warn("обрывов отложено больше %d за проход, %d не сделано",
                 ENG_PENDING_MAX, e->pending_lost);
        e->pending_lost = 0;
    }
    e->pending_count = 0;
}

/* Версия ядра — спросив у самого бинарника.

   Один раз, а не на каждый запрос страницы: строка не меняется, а
   порождать процесс каждые десять секунд ради неё незачем. Если ядра
   ещё нет, пробуем не чаще раза в минуту. */
static void note_xray_version(engine_t *e, time_t now)
{
    if (e->xray_version[0]) return;
    if (e->xray_ver_try && now - e->xray_ver_try < 60) return;
    e->xray_ver_try = now;

    char bin[APPLY_PATH_MAX] = "";
    if (e->cfg && e->cfg->xray_bin[0])
        str_copy(bin, sizeof(bin), e->cfg->xray_bin);
    else if (!apply_find_xray(bin, sizeof(bin)))
        return;

    char arg[] = "version";
    char *argv[] = { bin, arg, NULL };
    char  out[256] = "";

    if (proc_run(argv, out, sizeof(out), 5) != 0) return;

    /* «Xray 26.7.28 (Xray, Penetrates Everything.) ...» — второе слово. */
    const char *p = strchr(out, ' ');
    if (!p) return;
    p++;

    size_t n = strcspn(p, " \n\r");
    if (n == 0 || n >= sizeof(e->xray_version)) return;

    memcpy(e->xray_version, p, n);
    e->xray_version[n] = '\0';
    log_info("ядро Xray версии %s", e->xray_version);
}

static int load_lists(engine_t *e, const config_t *cfg)
{
    char domains[CFG_PATH_MAX + 32];
    char cidrs[CFG_PATH_MAX + 32];

    /* Память известных адресов хранит номер группы, а номера после
       перечитывания могут перераспределиться. Со старыми записями
       добавления подавлялись бы не для той группы. Цена сброса — один
       лишний обрыв на первый ClientHello к уже разложенному адресу. */
    e->known_count = 0;

    snprintf(domains, sizeof(domains), "%s/domain.conf", cfg->conf_dir);
    snprintf(cidrs,   sizeof(cidrs),   "%s/ip.list",     cfg->conf_dir);

    wl_init(&e->wl);
    wl_load_domains(&e->wl, domains);
    wl_load_cidrs(&e->wl, cidrs);

    log_info("списки: групп %d, доменов %d, подсетей %d, пропущено строк %d",
             e->wl.group_count, e->wl.domain_count, e->wl.cidr_count,
             e->wl.skipped);

    wl_classify_targets(&e->wl, NULL);
    return e->wl.group_count;
}

/* Перехват держим ровно тогда, когда есть кого ловить, и пересчитываем
   это при каждом перечитывании. Раньше он открывался один раз при
   старте и только если списки уже непусты: на свежей установке список
   пуст, и перехват не включался никогда — ни после добавления доменов
   через страницу, ни после SIGHUP. Снаружи это выглядело как «домены
   сохранены, правила стоят, а адресов ноль». */
static void sync_capture(engine_t *e, const config_t *cfg)
{
    /* Два перехвата сверяются по отдельности. Раньше ранний выход
       смотрел только на DNS: sniCapture=no по SIGHUP не выключал
       сокет, а не открывшийся при старте SNI никто не пробовал открыть
       снова — при живом DNS всё выглядело исправным. */
    int have     = e->wl.group_count > 0;
    int want_dns = have;
    int want_sni = have && cfg->sni_capture;

    if (!want_dns && e->capturing) {
        dcap_close(&e->cap);
        e->capturing = 0;
        log_info("перехват DNS остановлен: доменов не осталось");
    }
    if (!want_sni && e->sniffing) {
        scap_close(&e->sni);
        e->sniffing = 0;
        log_info("перехват SNI остановлен: %s",
                 have ? "выключен в конфиге" : "доменов не осталось");
    }

    if (want_dns && !e->capturing) {
        char cap_err[160] = "";
        if (dcap_open(&e->cap, cfg->capture_iface, cap_err, sizeof(cap_err)) == 0) {
            e->capturing = 1;
            log_info("перехват DNS на %s%s",
                     cfg->capture_iface[0] ? cfg->capture_iface : "всех интерфейсах",
                     e->cap.filtered ? "" : " (без фильтра ядра)");
        } else {
            /* Без перехвата домены наполняться не будут, но подсети из
               ip.list работают. Останавливаться из-за этого неправильно. */
            log_warn("перехват DNS недоступен: %s. Домены наполняться не будут, "
                     "подсети из ip.list работают", cap_err);
        }
    }

    /* Перехват SNI — второй канал, не замена первому. DNS даёт адрес
       заранее, до первого соединения; SNI видит то, чего DNS не видит
       вовсе: тёплый кеш устройства, свой DoH у клиента, зашитый адрес.
       Поэтому отказ одного не мешает другому. */
    if (want_sni && !e->sniffing) {
        char sni_err[160] = "";
        if (scap_open(&e->sni, cfg->capture_iface, sni_err, sizeof(sni_err)) == 0) {
            e->sniffing = 1;
            log_info("перехват SNI на %s",
                     cfg->capture_iface[0] ? cfg->capture_iface : "всех интерфейсах");
        } else {
            log_warn("перехват SNI недоступен: %s. Останутся слепые зоны: "
                     "тёплый кеш, свой DoH у клиента, зашитые адреса", sni_err);
        }
    }
}

/* Для целей-политик метку назначает роутер, и спросить её можно только
   у него. Без метки правило ставить нельзя: пустая увела бы трафик в
   никуда, поэтому такие группы просто пропускаются до следующей попытки. */
static void fetch_policy_marks(engine_t *e)
{

    for (int i = 0; i < e->wl.group_count; i++) {
        wl_group_t *g = &e->wl.groups[i];
        if (g->target != WL_TARGET_POLICY) continue;

        unsigned mark = 0;
        int      rc   = rci_policy_mark(&e->rci, g->iface, &mark);

        if (rc == -2) {
            if (!e->may_create_policy) {
                /* Заводить политику и сохранять конфигурацию роутера —
                   изменение его настроек. Делать это без разрешения
                   нельзя: однажды так на роутере завелась лишняя
                   политика с именем интерфейса. */
                log_error("политика %s не найдена. Создай её в панели "
                          "роутера или разреши createPolicy=yes",
                          g->iface);
            } else {
                log_info("политика %s не найдена, создаю", g->iface);
                if (rci_policy_create(&e->rci, g->iface) == 0)
                    rc = rci_policy_mark(&e->rci, g->iface, &mark);
            }
        }

        if (rc == 0 && mark) {
            g->policy_mark = mark;
            log_info("политика %s: метка 0x%x", g->iface, mark);
        } else {
            g->policy_mark = 0;
            log_warn("у политики %s пока нет метки, её трафик не метится",
                     g->iface);
        }
    }
}

/* Ставит наборы и правила. Наборы обязаны существовать до правил:
   iptables откажется ссылаться на несуществующий набор. */
static int apply_all(engine_t *e, char *err, unsigned err_size, int recreate)
{
    if (!e->wl.group_count) {
        log_info("групп нет, правила не ставятся");
        return 0;
    }

    fetch_policy_marks(e);

    /* Пересоздаём только когда время жизни записей и правда изменилось.
       Раньше это делалось при каждом перечитывании конфига — то есть при
       каждом сохранении списка и каждой правке настроек, — и вместе с
       наборами стирались все накопленные адреса. Снаружи выглядело так:
       сохранил домен, и половина сайтов пошла мимо туннеля, пока перехват
       не узнает адреса заново. */
    if (recreate) recreate = ips_timeout_differs(&e->ips, &e->wl, e->ipset_timeout);

    if (recreate) {
        /* Набор, созданный без времени жизни, не примет записи с ним, а
           изменить это у существующего набора нельзя — только пересоздать.
           Правила снимаем первыми: пока они ссылаются на набор, удалить
           его невозможно.

           При восстановлении по SIGUSR1 сюда не заходим: там пересоздание
           стёрло бы все накопленные адреса. */
        rt_plan_t rm;
        rt_plan_remove(&rm, &e->rt, &e->wl);
        char ignore[256];
        rt_run(&rm, &e->rt, ignore, sizeof(ignore));

        ips_destroy(&e->ips, &e->wl);
    }

    ips_queue_create(&e->ips, &e->wl, e->ipset_timeout);
    ips_queue_cidrs(&e->ips, &e->wl);
    if (ips_flush(&e->ips, err, err_size) != 0) return -1;

    rt_plan_t plan;
    rt_plan_apply(&plan, &e->rt, &e->wl);
    if (rt_run(&plan, &e->rt, err, err_size) != 0) return -1;

    e->rules_applied = 1;
    return 0;
}

/* Поднимает собственный Xray: читает ссылки, собирает конфиг, проверяет
   его тем же ядром и только потом запускает.

   Отсутствие файла со ссылками — не ошибка: тогда своего ядра просто
   нет, а маршрутизация продолжает работать через то подключение,
   которое настроено вручную. */
static void start_own_xray(engine_t *e, const config_t *cfg)
{
    /* Отметка от прежней кнопки «выключить ядро». Кнопки больше нет, и
       оставленный файл держал бы ядро выключенным без способа включить
       его обратно. Убираем при первом же запуске. */
    char stale[CFG_PATH_MAX + 32];
    snprintf(stale, sizeof(stale), "%s/core.off", cfg->conf_dir);
    if (unlink(stale) == 0)
        log_info("убрана прежняя отметка core.off, ядро запускается как обычно");
    FILE *f = fopen(cfg->nodes_file, "r");
    if (!f) {
        log_info("файла %s нет, свой Xray не запускается", cfg->nodes_file);
        return;
    }

    static char body[256 * 1024];
    size_t got       = fread(body, 1, sizeof(body) - 1, f);
    int    truncated = !feof(f);
    fclose(f);
    body[got] = '\0';

    if (truncated) {
        log_error("%s больше %zu байт", cfg->nodes_file, sizeof(body) - 1);
        return;
    }

    static nodelist_t list;
    nodelist_init(&list);
    int added = nodelist_from_subscription(&list, body);

    /* allowInsecure из ссылки в конфиг не переносится — см. xraycfg.c.
       Но молчать о том, что ссылка его просила, нельзя: человек будет
       искать, почему «не работает как в приложении». */
    for (int i = 0; i < list.count; i++)
        if (list.items[i].flow_dropped)
            log_warn("ссылка «%s»: flow снят — Vision работает только поверх tcp",
                     list.items[i].tag[0] ? list.items[i].tag : "без имени");
    for (int i = 0; i < list.count; i++)
        if (list.items[i].allow_insecure)
            log_warn("ссылка «%s» просит allowInsecure — не переношу: без "
                     "проверки сертификата TLS ничего не защищает",
                     list.items[i].tag[0] ? list.items[i].tag : "без имени");
    if (added <= 0) {
        log_error("в %s нет ни одной понятной ссылки", cfg->nodes_file);
        return;
    }
    if (list.skipped)
        log_warn("в %s пропущено строк: %d", cfg->nodes_file, list.skipped);

    /* Прокси-клиент Keenetic приходит на LAN-адрес роутера, а не на
       петлю, поэтому и слушать надо там. */
    char lan[64] = "";
    if (!iface_ipv4(cfg->capture_iface, lan, sizeof(lan))) {
        log_error("не узнать адрес на %s, свой Xray не запускается",
                  cfg->capture_iface);
        return;
    }

    xraycfg_opts_t o;
    xraycfg_defaults(&o);
    o.listen      = lan;
    o.socks_port  = cfg->socks_port;
    o.fragment    = cfg->fragment;
    o.fingerprint = cfg->fingerprint;
    o.error_log   = XRAY_ERROR_LOG;

    static char json[256 * 1024];
    if (xraycfg_build_list(&list, &o, json, sizeof(json)) != 0) {
        log_error("не удалось собрать конфиг Xray");
        return;
    }

    apply_opts_t ao;
    apply_defaults(&ao);
    str_copy(ao.config_path, sizeof(ao.config_path), cfg->xray_config);
    if (cfg->xray_bin[0]) str_copy(ao.xray_bin, sizeof(ao.xray_bin), cfg->xray_bin);

    char aerr[512] = "";
    if (apply_config(&ao, json, aerr, sizeof(aerr)) != 0) {
        /* Конфиг не принят — запускать ядро с ним нельзя. */
        log_error("Xray отверг конфиг: %s", aerr);
        return;
    }

    log_info("конфиг Xray записан: узлов %d, socks %s:%d",
             list.count, lan, cfg->socks_port);

    sv_init(&e->xray, ao.xray_bin, cfg->xray_config);
    if (sv_start(&e->xray) == 0) {
        e->xray_managed = 1;
        str_copy(e->xray_listen, sizeof(e->xray_listen), lan);
        /* Первую проверку — через несколько секунд: ядру надо успеть
           открыть порт. */
        e->probe_next = time(NULL) + ENGINE_PROBE_FIRST;
    }
}

/* Проверка туннеля: запуск по расписанию, продвижение по шагам, итог.
   Об изменении состояния пишем в журнал и сразу выкладываем статус,
   чтобы страница и --status не ждали минутного круга. */
static void tunnel_probe(engine_t *e, time_t now)
{
    if (e->probe.state != PROBE_IDLE && e->probe.state != PROBE_DONE) {
        if (!probe_poll(&e->probe, (long)now)) return;

        e->tunnel_at = now;
        int st = e->probe.ok ? 1 : -1;
        if (e->probe.ok) e->tunnel_ms = e->probe.ms;
        str_copy(e->tunnel_why, sizeof(e->tunnel_why), e->probe.why);

        if (st != e->tunnel_state) {
            e->tunnel_since = now;
            if (st > 0) log_info("туннель отвечает, %d мс", e->tunnel_ms);
            else        log_warn("туннель не отвечает: %s", e->tunnel_why);
            e->tunnel_state = st;
        }
        /* Файл состояния — после каждой проверки, а не раз в минуту:
           иначе --status показывал «проверен 107 с назад» при интервале
           в 60, потому что удачная повторная проверка ничего не меняла
           и записи не вызывала. */
        status_write(e, e->cfg);
        e->probe_next = now + (st > 0 ? ENGINE_PROBE_OK : ENGINE_PROBE_FAIL);
        probe_abort(&e->probe);
        return;
    }

    if (!e->xray_managed || e->xray.pid <= 0) return;
    if (!e->cfg || !e->cfg->probe_url[0] || !e->xray_listen[0]) return;
    if (now < e->probe_next) return;

    if (probe_start(&e->probe, e->xray_listen, e->cfg->socks_port,
                    e->cfg->probe_url, (long)now) != 0) {
        /* Не смогли даже начать: это тоже ответ. */
        e->tunnel_at = now;
        str_copy(e->tunnel_why, sizeof(e->tunnel_why), e->probe.why);
        if (e->tunnel_state != -1) {
            e->tunnel_state = -1;
            e->tunnel_since = now;
            log_warn("туннель не отвечает: %s", e->tunnel_why);
            status_write(e, e->cfg);
        }
        e->probe_next = now + ENGINE_PROBE_FAIL;
        probe_abort(&e->probe);
    }
}

/* Всё, что движок берёт из конфига, — в одном месте. Раньше это делал
   только engine_start, а engine_reload — нет: правишь createPolicy,
   ipsetTimeout или ipv6, шлёшь SIGHUP, и демон продолжает жить со
   старыми значениями до полного перезапуска. */
static void adopt_config(engine_t *e, const config_t *cfg)
{
    e->cfg               = cfg;
    e->rt.ipv6           = cfg->ipv6 && e->rt.ip6tables[0];
    e->rt.guard_port     = cfg->socks_port;
    e->may_create_policy = cfg->create_policy;
    e->ipset_timeout     = cfg->ipset_timeout;
}

int engine_start(engine_t *e, const config_t *cfg, char *err, unsigned err_size)
{
    if (!e || !cfg) return -1;

    e->started_at = time(NULL);

    if (!ips_find_bin(e->ips.bin, sizeof(e->ips.bin))) {
        if (err) str_copy(err, err_size, "не найден ipset");
        return -1;
    }
    if (!rt_find_bins(&e->rt)) {
        if (err) str_copy(err, err_size, "не найдены iptables или ip");
        return -1;
    }
    adopt_config(e, cfg);

    /* Своё ядро поднимаем до правил: пока оно не слушает, заворачивать
       туда трафик бессмысленно. */
    start_own_xray(e, cfg);

    int have = load_lists(e, cfg);

    if (have && apply_all(e, err, err_size, 1) != 0) return -1;

    sync_capture(e, cfg);

    status_write(e, cfg);
    return 0;
}

void engine_stop(engine_t *e)
{
    if (!e) return;

    probe_abort(&e->probe);
    if (e->xray_managed) {
        sv_stop(&e->xray);
        e->xray_managed = 0;
    }

    if (e->sniffing) {
        scap_close(&e->sni);
        e->sniffing = 0;
    }

    if (e->capturing) {
        dcap_close(&e->cap);
        e->capturing = 0;
    }

    if (e->rules_applied) {
        rt_plan_t plan;
        rt_plan_remove(&plan, &e->rt, &e->wl);

        char err[256] = "";
        if (rt_run(&plan, &e->rt, err, sizeof(err)) != 0)
            log_warn("не все правила сняты: %s", err);

        e->rules_applied = 0;
    }
}

int engine_reload(engine_t *e, const config_t *cfg, char *err, unsigned err_size)
{
    if (!e || !cfg) return -1;

    /* Движок мог так и не запуститься — autoStart=no. Тогда SIGHUP от
       первого же сохранения приходил в недособранный движок: без путей
       к iptables план исполнял литерал «<нет:iptables>», а файл
       состояния не писался никогда. Первое перечитывание — это старт. */
    if (!e->cfg) return engine_start(e, cfg, err, err_size);

    adopt_config(e, cfg);

    /* Старые правила снимаем по старым спискам: после перечитывания
       имена групп могут поменяться, и снимать станет нечего. */
    if (e->rules_applied) {
        rt_plan_t plan;
        rt_plan_remove(&plan, &e->rt, &e->wl);
        char ignore[256];
        rt_run(&plan, &e->rt, ignore, sizeof(ignore));
        e->rules_applied = 0;
    }

    /* Ссылки могли смениться вместе со списками, поэтому ядро
       перезапускаем: иначе трафик пошёл бы через прежний сервер. */
    probe_abort(&e->probe);
    if (e->xray_managed) {
        sv_stop(&e->xray);
        e->xray_managed = 0;
    }
    start_own_xray(e, cfg);

    int have = load_lists(e, cfg);

    /* Правила уже сняты, так что сейчас — единственный момент, когда
       наборы исчезнувших групп можно удалить: пока на них ссылаются
       правила, ядро их не отдаёт. */
    int gone = ips_destroy_orphans(&e->ips, &e->wl);
    if (gone) log_info("убрано наборов от прежних групп: %d", gone);

    /* Перехват пересчитываем всегда: именно здесь появляются домены,
       добавленные через страницу. */
    sync_capture(e, cfg);

    if (!have) return 0;
    return apply_all(e, err, err_size, 1);
}

void engine_request_restore(engine_t *e, time_t now)
{
    if (!e) return;
    /* Уже отложено — второй запрос ничего не меняет. */
    if (!e->restore_due) e->restore_due = now + ENGINE_RESTORE_DELAY;
}

int engine_restore(engine_t *e, char *err, unsigned err_size)
{
    if (!e) return -1;
    if (!e->wl.group_count) return 0;

    /* Роутер переписал netfilter — наши правила исчезли. План
       идемпотентен, поэтому его достаточно применить заново.

       Наборы при этом не трогаем: пересоздание стёрло бы все адреса,
       накопленные перехватом, и маршрутизация замолчала бы до
       следующего резолва каждого домена. */
    e->restores++;
    return apply_all(e, err, err_size, 0);
}

void engine_tick(engine_t *e, time_t now)
{
    if (!e) return;

    note_xray_version(e, now);

    if (e->capturing) dcap_poll(&e->cap, on_reply, e);
    if (e->sniffing) {
        scap_poll(&e->sni, on_sni, e);
        flush_pending_breaks(e);
    }

    /* Подхватываем падение своего ядра и перезапускаем с паузой. */
    if (e->xray_managed) sv_tick(&e->xray, now);
    tunnel_probe(e, now);

    if (e->restore_due && now >= e->restore_due) {
        e->restore_due = 0;
        char err[256] = "";
        if (engine_restore(e, err, sizeof(err)) != 0)
            log_warn("восстановить правила не удалось: %s", err);
        else
            log_info("правила восстановлены");
    }

    /* Раз в минуту показываем, что видит перехват. Пустой набор сам по
       себе не говорит, молчит ли сеть или сокет ничего не получает. */
    if (now - e->last_stats >= 60) {
        e->last_stats = now;
        rt_counters(&e->rt, &e->marked_conns, &e->restored_pkts);
        ips_count_entries(&e->ips, &e->wl, e->addr4, e->addr6);
        status_write(e, e->cfg);
    }

    if (e->capturing && now - e->last_stats_log >= 60) {
        e->last_stats_log = now;
        log_info("перехват: пакетов %lu, ответов %lu, адресов %lu; "
                 "мимо: не наш трафик %lu, без адресов %lu, битых %lu",
                 e->cap.seen, e->cap.parsed, e->matched,
                 e->cap.drop_notip, e->cap.drop_empty, e->cap.drop_bad);
    }

    if (e->ips.queued && now - e->last_flush >= ENGINE_FLUSH_SECONDS) {
        char err[256] = "";
        if (ips_flush(&e->ips, err, sizeof(err)) != 0)
            log_warn("ipset не принял пачку: %s", err);
        else
            e->flushes++;
        e->last_flush = now;
    }
}

void engine_print_plan(const engine_t *e)
{
    if (!e) return;

    /* Сначала — чем именно будем работать. Иначе, когда групп нет,
       из вывода не понять, нашлись ли программы вообще. */
    printf("# программы\n");
    printf("iptables:  %s\n",  e->rt.iptables[0]  ? e->rt.iptables  : "НЕ НАЙДЕН");
    printf("ip6tables: %s\n",  e->rt.ip6tables[0] ? e->rt.ip6tables : "нет, IPv6 выключен");
    printf("ip:        %s\n",  e->rt.ip[0]        ? e->rt.ip        : "НЕ НАЙДЕН");
    printf("ipset:     %s\n",  e->ips.bin[0]      ? e->ips.bin      : "НЕ НАЙДЕН");
    printf("\n");

    /* Без групп демон правил не ставит. Печатать план, который не будет
       применён, значит вводить в заблуждение. */
    if (!e->wl.group_count) {
        printf("# групп нет — правила ставиться не будут\n");
        printf("# заполни domain.conf или ip.list, затем повтори\n");
        return;
    }

    rt_plan_t plan;
    rt_plan_apply(&plan, &e->rt, &e->wl);

    printf("# цели\n");
    for (int i = 0; i < e->wl.group_count; i++) {
        const wl_group_t *g = &e->wl.groups[i];
        const char *kind =
            g->target == WL_TARGET_IFACE  ? "устройство" :
            g->target == WL_TARGET_POLICY ? "политика Keenetic" : "не задана";
        printf("%-16s %-18s %s", g->name, g->iface[0] ? g->iface : "-", kind);
        if (g->target == WL_TARGET_POLICY) {
            if (g->policy_mark) printf(", метка 0x%x", g->policy_mark);
            else                printf(", МЕТКА НЕ ПОЛУЧЕНА");
        }
        printf("\n");
    }
    printf("\n");

    printf("# наборы\n");
    ips_t preview;
    ips_init(&preview, "ipset");
    ips_queue_create(&preview, &e->wl, e->ipset_timeout);
    ips_queue_cidrs(&preview, &e->wl);
    fputs(ips_pending(&preview), stdout);

    printf("# правила\n");
    for (int i = 0; i < plan.count; i++) {
        char line[512];
        printf("%s%s\n", rt_cmd_text(&plan.cmds[i], line, sizeof(line)),
               plan.cmds[i].may_fail ? "   # отсутствие не ошибка" : "");
    }
}
