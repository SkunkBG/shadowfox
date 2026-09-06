#include "engine.h"
#include "log.h"
#include "util.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

/* Как часто отдавать накопленные адреса в ipset. Раз в секунду: адреса
   должны попадать в наборы быстро, иначе первое соединение к домену
   уйдёт мимо туннеля, а пачками — чтобы не порождать процесс на каждый
   ответ. */
#define ENGINE_FLUSH_SECONDS 1

void engine_init(engine_t *e)
{
    memset(e, 0, sizeof(*e));
    wl_init(&e->wl);
    ips_init(&e->ips, NULL);
    rt_init(&e->rt);
    dcap_init(&e->cap);
}

int engine_fd(const engine_t *e)
{
    return (e && e->capturing) ? e->cap.fd : -1;
}

/* Пойманный ответ: раскладываем адреса по группам. */
static void on_reply(const dns_reply_t *r, void *ctx)
{
    engine_t *e = ctx;

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

        log_debug("%s -> %s в группу %s", r->question, text,
                  e->wl.groups[group].name);
    }
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

    return e->wl.group_count;
}

/* Ставит наборы и правила. Наборы обязаны существовать до правил:
   iptables откажется ссылаться на несуществующий набор. */
static int apply_all(engine_t *e, char *err, unsigned err_size)
{
    if (!e->wl.group_count) {
        log_info("групп нет, правила не ставятся");
        return 0;
    }

    ips_queue_create(&e->ips, &e->wl);
    ips_queue_cidrs(&e->ips, &e->wl);
    if (ips_flush(&e->ips, err, err_size) != 0) return -1;

    rt_plan_t plan;
    rt_plan_apply(&plan, &e->rt, &e->wl);
    if (rt_run(&plan, &e->rt, err, err_size) != 0) return -1;

    e->rules_applied = 1;
    return 0;
}

int engine_start(engine_t *e, const config_t *cfg, char *err, unsigned err_size)
{
    if (!e || !cfg) return -1;

    if (!ips_find_bin(e->ips.bin, sizeof(e->ips.bin))) {
        if (err) str_copy(err, err_size, "не найден ipset");
        return -1;
    }
    if (!rt_find_bins(&e->rt)) {
        if (err) str_copy(err, err_size, "не найдены iptables или ip");
        return -1;
    }
    e->rt.ipv6 = cfg->ipv6 && e->rt.ip6tables[0];

    if (!load_lists(e, cfg)) return 0;

    if (apply_all(e, err, err_size) != 0) return -1;

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

    return 0;
}

void engine_stop(engine_t *e)
{
    if (!e) return;

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

    if (!load_lists(e, cfg)) return 0;
    return apply_all(e, err, err_size);
}

int engine_restore(engine_t *e, char *err, unsigned err_size)
{
    if (!e) return -1;
    if (!e->wl.group_count) return 0;

    /* Роутер переписал netfilter — наши правила исчезли. План
       идемпотентен, поэтому его достаточно применить заново. */
    e->restores++;
    return apply_all(e, err, err_size);
}

void engine_tick(engine_t *e, time_t now)
{
    if (!e) return;

    if (e->capturing) dcap_poll(&e->cap, on_reply, e);

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

    printf("# наборы\n");
    ips_t preview;
    ips_init(&preview, "ipset");
    ips_queue_create(&preview, &e->wl);
    ips_queue_cidrs(&preview, &e->wl);
    fputs(ips_pending(&preview), stdout);

    printf("# правила\n");
    for (int i = 0; i < plan.count; i++) {
        char line[512];
        printf("%s%s\n", rt_cmd_text(&plan.cmds[i], line, sizeof(line)),
               plan.cmds[i].may_fail ? "   # отсутствие не ошибка" : "");
    }
}
