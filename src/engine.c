#include "shadowfox.h"
#include "engine.h"
#include "apply.h"
#include "log.h"
#include "status.h"
#include "nodelist.h"
#include "xraycfg.h"
#include "xjson.h"
#include "proc.h"
#include "util.h"

#include <stdio.h>

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
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
/* Обрывов соединений в секунду. Было 20: на проводе это выглядело как
   шквал коротких TLS-сессий к одному адресу, и провайдер с
   распознаванием по поведению закрывал адрес сервера. Настоящему
   трафику новых адресов в секунду нужны единицы. */
#define ENGINE_BREAK_BUDGET  3

/* Как часто смотреть на сокеты ядра. Чтение /proc, ни одного пакета. */
#define ENGINE_TUNNEL_SAMPLE 30

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
    rttcap_init(&e->rttcap);
    e->tunnel_rtt_ms = -1;
}

int engine_fds(const engine_t *e, int *out, int max)
{
    if (!e || !out || max <= 0) return 0;

    int n = 0;
    if (e->capturing && n < max) out[n++] = e->cap.fd;
    if (e->sniffing  && n < max) out[n++] = e->sni.fd;
    if (e->rttcap.fd >= 0 && n < max) out[n++] = e->rttcap.fd;
    return n;
}

/* Помним, что адрес уже разложен по набору. Возвращает 1, если увидели
   его впервые.

   Срок жизни записи привязан к сроку жизни записи в самом наборе: как
   только адрес оттуда состарится, помнить о нём нам тоже незачем. */
static int note_addr(engine_t *e, int group, int family,
                     const unsigned char *addr, time_t now)
{
    /* Набор общий на цель: помним по владельцу набора, иначе адрес,
       узнанный через группу YouTube, для группы Google выглядел бы
       новым — и соединение рвалось бы зря. */
    group = wl_set_owner(&e->wl, group);
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

/* Наполняет память известных адресов тем, что уже лежит в наборах.
   Возраст записи восстанавливаем из остатка времени жизни, чтобы она
   состарилась в памяти тогда же, когда и в наборе. */
static void on_member(int group, int family, const char *addr, long remaining, void *ctx)
{
    engine_t     *e = ctx;
    unsigned char bin[16];
    int           af = family == 4 ? AF_INET : AF_INET6;
    if (inet_pton(af, addr, bin) != 1) return;

    time_t now = time(NULL);
    time_t ttl = e->ipset_timeout > 0 ? e->ipset_timeout : 86400;
    time_t at  = (remaining >= 0 && remaining < ttl) ? now - (ttl - remaining) : now;

    if (e->known_count >= ENG_KNOWN_MAX) return;
    int k = e->known_count++;
    memset(e->known[k].addr, 0, sizeof(e->known[k].addr));
    memcpy(e->known[k].addr, bin, family == 4 ? 4 : 16);
    e->known[k].family = (unsigned char)family;
    e->known[k].group  = (short)group;
    e->known[k].at     = at;
}

static void warm_known(engine_t *e)
{
    if (!e->ips.bin[0]) return;
    int rc = ips_list_members(&e->ips, &e->wl, on_member, e);
    if (rc != 0 && e->known_count == 0)
        log_warn("не прочитать наборы: первые соединения к известным адресам будут оборваны");
    else
        log_info("память адресов: %d из наборов%s", e->known_count,
                 rc != 0 ? " (список обрезан)" : "");
}

static int load_lists(engine_t *e, const config_t *cfg)
{
    char domains[CFG_PATH_MAX + 32];
    char cidrs[CFG_PATH_MAX + 32];

    /* Память известных адресов хранит номер группы, а номера после
       перечитывания могут перераспределиться. Со старыми записями
       добавления подавлялись бы не для той группы. Сбрасываем, а ниже
       наполняем заново из самих наборов: раньше «цена сброса» считалась
       одним лишним обрывом, а на деле в первую минуту после каждого
       запуска рвалось каждое соединение к уже разложенному адресу —
       десятки TLS-сессий к серверу подряд, и провайдер закрывал его. */
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
    warm_known(e);
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
    /* Сначала убрать наши правила, которые больше не соответствуют
       спискам (сменилась метка, цель, группа выключена), потом
       поставить недостающие. Совпадающие не трогаются вовсе. */
    int pruned = rt_prune_stale(&e->rt, &e->wl);
    if (pruned) log_info("снято устаревших правил: %d", pruned);

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
/* Ссылок больше нет или они негодны — ядро со старыми гасим: иначе
   трафик шёл бы через сервер, которого в файле уже нет. */
static void stop_own_xray(engine_t *e, const char *why)
{
    if (!e->xray_managed) return;
    log_info("ядро останавливается: %s", why);
    sv_stop(&e->xray);
    e->xray_managed = 0;
}

static void start_own_xray_ex(engine_t *e, const config_t *cfg, int force)
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
        e->subs_urls = 0;   /* иначе расписание подписки дёргало бы нас каждую секунду */
        stop_own_xray(e, "файла ссылок нет");
        return;
    }

    static char body[256 * 1024];
    size_t got       = fread(body, 1, sizeof(body) - 1, f);
    int    truncated = !feof(f);

    /* Файл ссылок сохранили заново — подписку качаем заново, даже если
       адрес тот же: так «Заменить подключение» подтягивает свежий
       список. Сохранение правил файл не трогает, и оно в панель не ходит. */
    struct stat st;
    if (fstat(fileno(f), &st) == 0 && st.st_mtime != e->nodes_mtime) {
        if (e->nodes_mtime) force = 1;
        e->nodes_mtime = st.st_mtime;
    }
    fclose(f);
    body[got] = '\0';
    if (e->subs_force) { force = 1; e->subs_force = 0; }

    if (truncated) {
        log_error("%s больше %zu байт", cfg->nodes_file, sizeof(body) - 1);
        e->subs_urls = 0;
        stop_own_xray(e, "файл ссылок не прочитан");
        return;
    }

    /* Подписки: адреса https:// раскрываются в список ссылок. Не при
       каждом перечитывании: списки на странице сохраняют часто, а
       каждая загрузка — соединение с панелью, которое провайдер видит.
       Загрузка держит главный цикл до её конца (обычно секунда-две,
       предел 40 с) — раз в шесть часов это терпимо. */
    static char raw[256 * 1024], expanded[256 * 1024];
    const char *text = body;
    e->subs_urls = subs_count_urls(body);
    if (e->subs_urls) {
        time_t now   = time(NULL);
        int    fresh = e->subs_ok && strcmp(raw, body) == 0 &&
                       now - e->subs_at < ENGINE_SUBS_REFRESH;
        if (force || !fresh) {
            char cache[CFG_PATH_MAX + 40], why[160] = "";
            int  cached = 0;
            snprintf(cache, sizeof(cache), "%s/" SUBS_CACHE, cfg->conf_dir);
            /* Адрес сменился — прежний кеш от другой панели, ему не место
               в запасе: при недоступной новой панели поднялись бы чужие
               серверы. */
            if (raw[0] && strcmp(raw, body) != 0) unlink(cache);
            /* Постоянный идентификатор устройства для панели. */
            char hpath[CFG_PATH_MAX + 40], hwid[64] = "";
            snprintf(hpath, sizeof(hpath), "%s/" SUBS_HWID_FILE, cfg->conf_dir);
            if (!secret_load_or_create(hpath, hwid, sizeof(hwid)))
                log_warn("не создать %s — подписка без x-hwid", hpath);
            /* Модель и прошивку спрашиваем у роутера один раз: панель
               покажет их в списке устройств пользователя. */
            if (!e->dev_asked) {
                e->dev_asked = 1;
                if (rci_device_info(&e->rci, e->dev_model, sizeof(e->dev_model),
                                    e->dev_osver, sizeof(e->dev_osver)) != 0)
                    log_info("модель роутера не узнать, панели уйдёт «Keenetic»");
            }
            subs_dev_t dev = { hwid, e->dev_model, e->dev_osver };
            int rc = subs_expand(body, cache, &dev, expanded, sizeof(expanded),
                                 &cached, why, sizeof(why));
            subs_first_host(body, e->subs_host, sizeof(e->subs_host));
            str_copy(raw, sizeof(raw), body);
            e->subs_at     = now;
            e->subs_cached = cached;
            e->subs_ok     = rc > 0;
            str_copy(e->subs_error, sizeof(e->subs_error), why);
            if (rc < 0) {
                log_error("подписка %s: %s", e->subs_host, why);
                e->server_count = 0;
                e->server_active[0] = '\0';
                stop_own_xray(e, "подписка не загружена");
                return;
            }
            if (cached)
                log_warn("подписка %s: сервер не ответил (%s), список из кеша",
                         e->subs_host, why);
            else
                log_info("подписка %s загружена", e->subs_host);
        }
        text = expanded;
    } else {
        e->subs_ok = 0;
        e->subs_host[0] = '\0';
    }

    /* Подписка в формате Xray JSON: панель отдаёт готовые конфиги ядра,
       в них бывает сборка из нескольких серверов с балансировщиком.
       Такой конфиг уходит ядру как есть, см. xraycfg_build_from_json. */
    static xjson_t xj;
    int json_mode = xjson_looks_like(text);
    if (json_mode) {
        int n = xjson_parse(text, &xj);
        if (n <= 0) {
            log_error("в %s нет ни одного конфига Xray", cfg->nodes_file);
            stop_own_xray(e, "конфигов нет");
            return;
        }
        if (xj.skipped) log_warn("конфигов без outbounds пропущено: %d", xj.skipped);
    }

    static nodelist_t list;
    nodelist_init(&list);
    int added = json_mode ? xj.count : nodelist_from_subscription(&list, text);

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
        stop_own_xray(e, "ссылок не осталось");
        return;
    }
    if (list.skipped)
        log_warn("в %s пропущено строк: %d", cfg->nodes_file, list.skipped);

    /* Имена серверов: из ссылок либо из remarks конфигов. */
    int total = json_mode ? xj.count : list.count;
    const char *names[XJSON_MAX > NODELIST_MAX ? XJSON_MAX : NODELIST_MAX];
    for (int i = 0; i < total; i++)
        names[i] = json_mode ? xj.items[i].remarks : list.items[i].tag;

    /* Метка в имени: панель отдаёт одну подписку и телефону, и роутеру,
       а серверы для роутера в ней помечены знаком в имени, по умолчанию
       «=». Тег хоста Remnawave в подписку не попадает, так что метка —
       единственное, по чему их отличить. Нет ни одного совпадения —
       берутся все: без метки подписка работает как обычно. Свою метку
       можно задать файлом server.filter. */
    int keep[XJSON_MAX > NODELIST_MAX ? XJSON_MAX : NODELIST_MAX], kept = 0;
    {
        char fpath[CFG_PATH_MAX + 40];
        snprintf(fpath, sizeof(fpath), "%s/" SERVER_FILTER_FILE, cfg->conf_dir);
        e->server_filter[0] = '\0';
        FILE *ff = fopen(fpath, "r");
        if (ff) {
            if (!fgets(e->server_filter, sizeof(e->server_filter), ff))
                e->server_filter[0] = '\0';
            fclose(ff);
            e->server_filter[strcspn(e->server_filter, "\r\n")] = '\0';
            str_copy(e->server_filter, sizeof(e->server_filter), str_trim(e->server_filter));
        }
        if (!e->server_filter[0])
            str_copy(e->server_filter, sizeof(e->server_filter), SERVER_FILTER_DEFAULT);
        if (total > 1) {
            for (int i = 0; i < total; i++)
                if (strcasestr(names[i], e->server_filter)) keep[kept++] = i;
            if (kept > 0 && kept < total)
                log_info("метка «%s»: серверов %d из %d", e->server_filter, kept, total);
            else if (!kept)
                log_info("метки «%s» нет ни у одного из %d серверов, показаны все",
                         e->server_filter, total);
        }
        if (!kept) for (int i = 0; i < total; i++) keep[kept++] = i;
    }

    /* Список серверов — на страницу; ядру один, выбранный там же.
       Балансировщик со всеми ссылками сразу — только по balancer=yes;
       у конфига из JSON балансировщик свой, внутри. */
    e->server_count = kept;
    for (int k = 0; k < kept; k++)
        str_copy(e->server_tags[k], sizeof(e->server_tags[k]), names[keep[k]]);

    int pick = keep[0];
    if (kept > 1) {
        char want[NODE_TAG_MAX] = "";
        char spath[CFG_PATH_MAX + 40];
        snprintf(spath, sizeof(spath), "%s/" SERVER_FILE, cfg->conf_dir);
        FILE *sf = fopen(spath, "r");
        if (sf) {
            if (!fgets(want, sizeof(want), sf)) want[0] = '\0';
            fclose(sf);
            want[strcspn(want, "\r\n")] = '\0';
        }
        int found = 0;
        for (int k = 0; k < kept; k++)
            if (want[0] && !strcmp(names[keep[k]], want)) { pick = keep[k]; found = 1; }
        if (want[0] && !found)
            log_warn("сервера «%s» в списке нет, взят первый: «%s»", want, names[pick]);
    }

    const xjson_item_t *chosen = NULL;
    int one = json_mode || !cfg->balancer;
    if (json_mode) {
        chosen = &xj.items[pick];
        if (kept > 1) log_info("конфигов в списке %d, ядру отдан «%s»", kept, names[pick]);
    } else if (one) {
        if (pick) list.items[0] = list.items[pick];
        list.count = 1;
        if (total > 1) log_info("серверов в списке %d, ядру отдан «%s»", kept, names[pick]);
    } else if (kept < total) {
        static nodelist_t tmp;
        nodelist_init(&tmp);
        for (int k = 0; k < kept; k++) tmp.items[tmp.count++] = list.items[keep[k]];
        list = tmp;
    }
    str_copy(e->server_active, sizeof(e->server_active),
             one ? names[pick] : "все сразу (balancer)");

    /* Прокси-клиент Keenetic приходит на LAN-адрес роутера, а не на
       петлю, поэтому и слушать надо там. */
    char lan[64] = "";
    if (!iface_ipv4(cfg->capture_iface, lan, sizeof(lan))) {
        log_error("не узнать адрес на %s, свой Xray не запускается",
                  cfg->capture_iface);
        stop_own_xray(e, "нет адреса интерфейса");
        return;
    }

    xraycfg_opts_t o;
    xraycfg_defaults(&o);
    o.listen      = lan;
    o.socks_port  = cfg->socks_port;
    o.fragment    = cfg->fragment;
    o.fingerprint = cfg->fingerprint;
    o.error_log   = XRAY_ERROR_LOG;

    static char secret[64];
    secret[0] = '\0';
    if (cfg->socks_secret[0]) {
        if (secret_load_or_create(cfg->socks_secret, secret, sizeof(secret))) {
            o.socks_user = "shadowfox";
            o.socks_pass = secret;
        } else {
            log_warn("не создать %s — SOCKS без пароля", cfg->socks_secret);
        }
    }

    static char json[256 * 1024];
    char berr[128] = "";
    int built = json_mode ? xraycfg_build_from_json(chosen, &o, json, sizeof(json), berr, sizeof(berr))
                          : xraycfg_build_list(&list, &o, json, sizeof(json));
    if (built != 0) {
        log_error("не удалось собрать конфиг Xray%s%s", berr[0] ? ": " : "", berr);
        if (json_mode) stop_own_xray(e, "конфиг панели отвергнут");
        return;
    }

    /* Конфиг тот же и ядро живо — не перезапускаем. Раньше любое
       сохранение списков на странице перезапускало ядро: все соединения
       через туннель рвались, и клиенты разом открывали десятки новых
       рукопожатий к серверу. Пять таких волн за шесть минут — и
       провайдер закрыл адрес сервера. Ядро касается только ссылок. */
    if (e->xray_managed && e->xray.pid > 0) {
        static char current[256 * 1024];
        FILE *cf = fopen(cfg->xray_config, "r");
        size_t clen = cf ? fread(current, 1, sizeof(current) - 1, cf) : 0;
        if (cf) fclose(cf);
        current[clen] = '\0';
        if (clen && strcmp(current, json) == 0) {
            log_info("конфиг Xray не изменился, ядро работает дальше");
            return;
        }
        stop_own_xray(e, "конфиг изменился");
    }

    apply_opts_t ao;
    apply_defaults(&ao);
    str_copy(ao.config_path, sizeof(ao.config_path), cfg->xray_config);
    if (cfg->xray_bin[0]) str_copy(ao.xray_bin, sizeof(ao.xray_bin), cfg->xray_bin);

    char aerr[512] = "";
    if (apply_config(&ao, json, aerr, sizeof(aerr)) != 0) {
        /* Конфиг не принят — запускать ядро с ним нельзя. Прежнее, если
           живо, пусть работает: рабочий сервер лучше никакого. */
        log_error("Xray отверг конфиг: %s", aerr);
        return;
    }

    log_info("конфиг Xray записан: %s, socks %s:%d",
             json_mode ? "конфиг из подписки JSON" : "из ссылок", lan, cfg->socks_port);

    /* Порты серверов — по ним пассивная проверка отличает соединения
       ядра с сервером от его же соединений с клиентами. */
    e->node_port_count = 0;
    if (json_mode) e->node_port_count = xjson_ports(chosen, e->node_ports, TCPSTAT_PORTS_MAX);
    for (int i = 0; !json_mode && i < list.count && e->node_port_count < TCPSTAT_PORTS_MAX; i++) {
        int port = list.items[i].port, dup = 0;
        for (int k = 0; k < e->node_port_count; k++) if (e->node_ports[k] == port) dup = 1;
        if (!dup) e->node_ports[e->node_port_count++] = port;
    }

    sv_init(&e->xray, ao.xray_bin, cfg->xray_config);
    if (sv_start(&e->xray) == 0) {
        e->xray_managed = 1;
        str_copy(e->xray_listen, sizeof(e->xray_listen), lan);
    }
}

static void start_own_xray(engine_t *e, const config_t *cfg)
{
    start_own_xray_ex(e, cfg, 0);
}

void engine_refresh_subscription(engine_t *e)
{
    if (e) e->subs_force = 1;
}

/* Пассивная проверка: сокеты ядра к серверу. Установленные есть —
   туннель жив. Только SYN без ответа — адрес сервера для нас закрыт.
   «Не отвечает» держится, пока не появится установленное: между
   попытками ядра сокетов нет вовсе, и без этого состояние мигало бы
   «нет данных». */
static void tunnel_sample(engine_t *e, time_t now)
{
    if (!e->xray_managed || e->xray.pid <= 0 || !e->node_port_count) return;
    if (now - e->tunnel_sampled < ENGINE_TUNNEL_SAMPLE) return;
    e->tunnel_sampled = now;

    tcpstat_t st;
    if (tcpstat_collect(e->xray.pid, e->node_ports, e->node_port_count, &st) != 0) return;

    e->tunnel_established  = st.established;
    e->tunnel_pending      = st.syn_sent;

    /* Задержка до сервера — из tcp_info живых соединений ядра. Наружу
       ничего не шлём; нет соединений или sock_diag — просто нет числа. */
    e->tunnel_rtt_ms = -1;
    if (st.established > 0) {
        static unsigned long inodes[TCPSTAT_INODES_MAX];
        int n = tcpstat_inodes(e->xray.pid, inodes, TCPSTAT_INODES_MAX);
        sockrtt_t rtt;
        if (n > 0 && sockrtt_collect(inodes, n, e->node_ports, e->node_port_count, &rtt) == 0)
            e->tunnel_rtt_ms = sockrtt_ms(&rtt);
    }
    /* Второй способ, для ядер без sock_diag: адреса серверов и порты —
       наблюдению за SYN, а замер — медиана свежих рукопожатий. */
    rttcap_set_ports(&e->rttcap, e->node_ports, e->node_port_count);
    rttcap_set_targets(&e->rttcap, (const unsigned char (*)[16])st.remotes,
                       st.remote_fam, st.remote_count);
    if (e->tunnel_rtt_ms < 0) e->tunnel_rtt_ms = rttcap_ms(&e->rttcap, now);
    e->tunnel_retrans_grow = st.established > 0 && st.retrans > e->tunnel_retrans_prev;
    e->tunnel_retrans_prev = st.retrans;
    e->tunnel_retrans      = st.retrans;

    int next = e->tunnel_state;
    const char *why = "";
    if (st.established > 0) {
        next = 1;
        if (e->tunnel_retrans_grow) why = "данные повторяются, сервер не подтверждает";
    } else if (st.syn_sent > 0) {
        next = -1;
        why = "ядро стучится к серверу, ответа нет";
    }
    str_copy(e->tunnel_why, sizeof(e->tunnel_why), why);

    if (next != e->tunnel_state) {
        e->tunnel_state = next;
        e->tunnel_since = now;
        if (next > 0) log_info("туннель: соединения с сервером установлены");
        else          log_warn("туннель: %s", why);
        status_write(e, e->cfg);
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

    /* Задержка до сервера по SYN/SYN-ACK его же соединений: своих
       пакетов нет, только наблюдение. Не открылось — просто без числа. */
    {
        char rerr[128] = "";
        if (rttcap_open(&e->rttcap, rerr, sizeof(rerr)) != 0)
            log_info("наблюдение задержки недоступно: %s", rerr);
    }

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
    rttcap_close(&e->rttcap);

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

    /* Ссылки могли смениться вместе со списками. Перезапустит ли ядро,
       решает start_own_xray, сравнив новый конфиг с записанным. Это
       делается до снятия правил: загрузка подписки может занять до
       40 секунд, и всё это время трафик обязан идти в туннель, а не
       напрямую к провайдеру. */
    start_own_xray(e, cfg);

    /* Старые правила снимаем по старым спискам: после перечитывания
       имена групп могут поменяться, и снимать станет нечего. */
    if (e->rules_applied) {
        rt_plan_t plan;
        rt_plan_remove(&plan, &e->rt, &e->wl);
        char ignore[256];
        rt_run(&plan, &e->rt, ignore, sizeof(ignore));
        e->rules_applied = 0;
    }

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
    rttcap_poll(&e->rttcap, now);
    if (e->sniffing) {
        scap_poll(&e->sni, on_sni, e);
        flush_pending_breaks(e);
    }

    /* Подхватываем падение своего ядра и перезапускаем с паузой. */
    if (e->xray_managed) sv_tick(&e->xray, now);
    tunnel_sample(e, now);

    /* Подписка по расписанию: список серверов у панели меняется. */
    if (e->subs_urls && e->cfg) {
        time_t due = e->subs_at + ((e->subs_ok && !e->subs_cached) ? ENGINE_SUBS_REFRESH
                                                                  : ENGINE_SUBS_RETRY);
        if (now >= due) start_own_xray_ex(e, e->cfg, 1);
    }

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
        rt_counters(&e->rt, &e->wl, &e->marked_conns, &e->restored_pkts);
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
    printf("iptables-restore: %s\n", e->rt.iptables_restore[0] ? e->rt.iptables_restore
                                       : "нет — цепочка ставится по команде, с зазором");
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

    if (plan.batch4[0]) { printf("# iptables-restore --noflush <<EOF\n%sEOF\n", plan.batch4); }
    if (plan.batch6[0]) { printf("# ip6tables-restore --noflush <<EOF\n%sEOF\n", plan.batch6); }

    printf("# правила\n");
    for (int i = 0; i < plan.count; i++) {
        char line[512];
        printf("%s%s\n", rt_cmd_text(&plan.cmds[i], line, sizeof(line)),
               plan.cmds[i].ensure   ? "   # если проверка не прошла — поставить" :
               plan.cmds[i].may_fail ? "   # отсутствие не ошибка" : "");
    }
}
