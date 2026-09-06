#include "engine.h"
#include "apply.h"
#include "log.h"
#include "status.h"
#include "nodelist.h"
#include "xraycfg.h"
#include "util.h"

#include <stdio.h>

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

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

void engine_init(engine_t *e)
{
    memset(e, 0, sizeof(*e));
    wl_init(&e->wl);
    ips_init(&e->ips, NULL);
    rt_init(&e->rt);
    dcap_init(&e->cap);
    rci_init(&e->rci);
    sv_init(&e->xray, "", "");
}

int engine_fd(const engine_t *e)
{
    return (e && e->capturing) ? e->cap.fd : -1;
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

static int load_lists(engine_t *e, const config_t *cfg)
{
    char domains[CFG_PATH_MAX + 32];
    char cidrs[CFG_PATH_MAX + 32];

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
    int want = e->wl.group_count > 0;
    if (want == e->capturing) return;

    if (!want) {
        dcap_close(&e->cap);
        e->capturing = 0;
        log_info("перехват DNS остановлен: доменов не осталось");
        return;
    }

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

/* Для целей-политик метку назначает роутер, и спросить её можно только
   у него. Без метки правило ставить нельзя: пустая увела бы трафик в
   никуда, поэтому такие группы просто пропускаются до следующей попытки. */
static void fetch_policy_marks(engine_t *e)
{
    e->policies_pending = 0;

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
            e->policies_pending++;
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
    e->servers = 0;

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
    if (added <= 0) {
        log_error("в %s нет ни одной понятной ссылки", cfg->nodes_file);
        return;
    }
    if (list.skipped)
        log_warn("в %s пропущено строк: %d", cfg->nodes_file, list.skipped);

    /* Раскладку запоминаем сразу после разбора, а не после запуска ядра:
       страница по ней подсказывает порты для подключений в роутере, и эта
       подсказка нужна как раз тогда, когда ничего ещё не работает. */
    e->servers = list.server_count < ENGINE_SERVERS_MAX
               ? list.server_count : ENGINE_SERVERS_MAX;
    for (int k = 0; k < e->servers; k++) {
        str_copy(e->server_name[k], sizeof(e->server_name[k]),
                 list.servers[k].name);
        e->server_port[k]  = nodelist_port(&list, k, cfg->socks_port);
        e->server_nodes[k] = list.servers[k].nodes;
    }

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
    o.listen     = lan;
    o.socks_port = cfg->socks_port;

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

    log_info("конфиг Xray записан: серверов %d, узлов %d",
             list.server_count, list.count);
    for (int k = 0; k < list.server_count; k++)
        log_info("  %s: узлов %d, socks %s:%d", list.servers[k].name,
                 list.servers[k].nodes, lan,
                 nodelist_port(&list, k, cfg->socks_port));

    sv_init(&e->xray, ao.xray_bin, cfg->xray_config);
    if (sv_start(&e->xray) == 0) e->xray_managed = 1;
}

int engine_start(engine_t *e, const config_t *cfg, char *err, unsigned err_size)
{
    if (!e || !cfg) return -1;

    e->started_at = time(NULL);
    e->cfg        = cfg;

    if (!ips_find_bin(e->ips.bin, sizeof(e->ips.bin))) {
        if (err) str_copy(err, err_size, "не найден ipset");
        return -1;
    }
    if (!rt_find_bins(&e->rt)) {
        if (err) str_copy(err, err_size, "не найдены iptables или ip");
        return -1;
    }
    e->rt.ipv6          = cfg->ipv6 && e->rt.ip6tables[0];
    e->may_create_policy = cfg->create_policy;
    e->ipset_timeout     = cfg->ipset_timeout;

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

    if (e->capturing) dcap_poll(&e->cap, on_reply, e);

    /* Подхватываем падение своего ядра и перезапускаем с паузой. */
    if (e->xray_managed) sv_tick(&e->xray, now);

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
