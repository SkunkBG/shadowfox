#include "webui.h"

#include "digest.h"
#include "ndmauth.h"
#include "proc.h"
#include "routercfg.h"

#define DNS_LINES_MAX 32

#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <time.h>

/* За сколько секунд считаем наблюдение свежим. Десять минут: реже этого
   устройство в сети без запросов почти не бывает, а короче — начнутся
   ложные тревоги у того, кто просто открыл страницу и ничего не делал. */
#define DNS_CHECK_WINDOW  600
#include "apply.h"
#include "engine.h"
#include "ipsets.h"
#include "jsonw.h"
#include "log.h"
#include "rci.h"
#include "util.h"
#include "watchlist.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>

extern const unsigned char web_page[];
extern const size_t        web_page_len;
extern const unsigned char web_logo[];
extern const size_t        web_logo_len;
extern const unsigned char web_font[];
extern const size_t        web_font_len;

static long slurp(const char *path, char *dst, size_t size);

typedef struct {
    struct engine  *engine;
    const config_t *cfg;
} webctx_t;

/* Адрес, на котором должен слушать интерфейс: либо задан явно, либо
   берётся с интерфейса захвата. Вынесено, чтобы перечитывание конфига
   могло сравнить желаемое с текущим, не открывая сокет. */
int webui_addr(const config_t *cfg, char *out, unsigned size,
               char *err, unsigned err_size)
{
    if (!cfg || !out) return -1;

    if (cfg->web_bind[0]) {
        str_copy(out, size, cfg->web_bind);
        return 0;
    }
    if (iface_ipv4(cfg->capture_iface, out, size)) return 0;

    if (err)
        snprintf(err, err_size,
                 "не узнать адрес на %s, задай webBind", cfg->capture_iface);
    return -1;
}

/* Нужно ли пересоздавать слушателя. Пересоздание не бесплатно: порт
   какое-то время занят прежними соединениями, и повторный bind падает
   с «Address in use» — после чего интерфейс лежал до перезапуска. */
int webui_needs_rebind(const http_t *h, const config_t *cfg)
{
    if (!h || !cfg) return 1;
    if (h->fd < 0) return 1;

    char addr[64];
    if (webui_addr(cfg, addr, sizeof(addr), NULL, 0) != 0) return 1;

    return strcmp(h->bind_addr, addr) != 0 || h->port != cfg->web_port;
}

int webui_open(http_t *h, const config_t *cfg, char *err, unsigned err_size)
{
    if (!h || !cfg) return -1;

    char addr[64];
    if (webui_addr(cfg, addr, sizeof(addr), err, err_size) != 0) return -1;

    http_init(h);

    /* Токен слою HTTP не отдаём: он требовал бы заголовок на каждый
       запрос, включая саму форму входа, и заданный webToken ломал бы
       обычный вход по паролю. Разрешает доступ теперь один слой — этот. */

    return http_open(h, addr, cfg->web_port, err, err_size);
}

/* Читает файл целиком. Возвращает длину либо -1. */
static long slurp(const char *path, char *dst, size_t size)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        if (size) dst[0] = '\0';
        return (errno == ENOENT) ? 0 : -1;
    }

    size_t got = fread(dst, 1, size - 1, f);
    int    big = !feof(f);
    fclose(f);

    dst[got] = '\0';
    return big ? -1 : (long)got;
}

static void path_in_conf(const config_t *cfg, const char *name,
                         char *dst, size_t size)
{
    snprintf(dst, size, "%s/%s", cfg->conf_dir, name);
}

/* Какому файлу соответствует раздел страницы. */
static int file_for(const config_t *cfg, const char *what,
                    char *dst, size_t size)
{
    if (!strcmp(what, "domains")) { path_in_conf(cfg, "domain.conf", dst, size); return 1; }
    if (!strcmp(what, "cidrs"))   { path_in_conf(cfg, "ip.list",     dst, size); return 1; }
    if (!strcmp(what, "nodes"))   { str_copy(dst, size, cfg->nodes_file);        return 1; }
    return 0;
}

/* Маскировка ссылок. Ключ — учётные данные, и отдавать его странице на
   каждом обновлении незачем: достаточно показать, куда ведёт ссылка.
   Прятать в разметке было бы обманом — текст всё равно уехал бы в
   браузер и осел в кеше. */
#define MASK_MARK "\xe2\x80\xa2\xe2\x80\xa2\xe2\x80\xa2\xe2\x80\xa2"   /* •••• */

static void mask_link(const char *in, char *out, size_t size)
{
    const char *scheme = strstr(in, "://");
    if (!scheme) { str_copy(out, size, in); return; }

    const char *rest = scheme + 3;
    const char *at   = strchr(rest, '@');
    const char *hash = strchr(rest, '#');

    /* Подписка целиком секрет: у неё вся ссылка — это доступ. */
    if (!at || (hash && at > hash)) {
        size_t head = (size_t)(rest - in);
        const char *slash = strchr(rest, '/');
        size_t host = slash ? (size_t)(slash - rest) : strlen(rest);
        snprintf(out, size, "%.*s%.*s/" MASK_MARK,
                 (int)head, in, (int)host, rest);
        return;
    }

    /* Ссылка на узел: прячем uuid и sid, остальное полезно видеть. */
    size_t head = (size_t)(rest - in);
    char   tail[512];
    str_copy(tail, sizeof(tail), at + 1);

    char *sid = strstr(tail, "sid=");
    if (sid) {
        char *end = sid + 4;
        while (*end && *end != '&' && *end != '#') end++;
        memmove(sid + 4 + 4, end, strlen(end) + 1);
        memcpy(sid + 4, "****", 4);
    }

    snprintf(out, size, "%.*s" MASK_MARK "@%s", (int)head, in, tail);
}

static void mask_nodes(const char *in, char *out, size_t size)
{
    size_t used = 0;
    out[0] = '\0';

    const char *p = in;
    while (*p) {
        const char *nl  = strchr(p, '\n');
        size_t      len = nl ? (size_t)(nl - p) : strlen(p);

        char line[1024];
        if (len >= sizeof(line)) len = sizeof(line) - 1;
        memcpy(line, p, len);
        line[len] = '\0';

        char shown[1024];
        if (line[0]) mask_link(str_trim(line), shown, sizeof(shown));
        else         shown[0] = '\0';

        int n = snprintf(out + used, size - used, "%s\n", shown);
        if (n < 0 || (size_t)n >= size - used) break;
        used += (size_t)n;

        if (!nl) break;
        p = nl + 1;
    }
}

/* Строковое поле верхнего уровня из ответа RCI. Разбор нарочно грубый:
   ответ короткий и свой, а тащить разборщик JSON ради трёх полей в
   подвале несоразмерно. */
static int json_field(const char *text, const char *name,
                      char *out, unsigned out_size)
{
    char pat[64];
    int  n = snprintf(pat, sizeof(pat), "\"%s\":\"", name);
    if (n < 0 || (size_t)n >= sizeof(pat)) return 0;

    const char *p = strstr(text, pat);
    if (!p) return 0;
    p += n;

    unsigned i = 0;
    while (*p && *p != '"' && i + 1 < out_size) {
        if (*p == '\\' && p[1]) p++;      /* экранированное — как есть */
        out[i++] = *p++;
    }
    out[i] = '\0';
    return i > 0;
}

static void send_data(const http_req_t *req, int fd, struct engine *ce,
                      const config_t *cfg)
{
    engine_t *e = (engine_t *)ce;

    static char buf[192 * 1024];
    json_t j;
    json_init(&j, buf, sizeof(buf));

    json_obj_open(&j);
    json_kv_str(&j, "version", VERSION);

    long up = e->started_at ? (long)time(NULL) - (long)e->started_at : 0;
    char uptime[64];
    snprintf(uptime, sizeof(uptime), "%ldч %ldм", up / 3600, (up % 3600) / 60);
    json_kv_str(&j, "uptime", uptime);

    json_kv_int(&j, "xray_pid", e->xray.pid);
    json_kv_bool(&j, "capture", e->capturing);
    json_kv_str(&j, "iface", cfg->capture_iface);
    json_kv_int(&j, "seen", (long)e->cap.seen);
    json_kv_int(&j, "parsed", (long)e->cap.parsed);
    json_kv_int(&j, "matched", (long)e->matched);
    json_kv_bool(&j, "rules", e->rules_applied);
    json_kv_int(&j, "marked", (long)e->marked_conns);

    /* Что уже сделано, а что нет: без этого со страницы непонятно,
       какой шаг настройки следующий. */
    char xbin[APPLY_PATH_MAX] = "";
    if (cfg->xray_bin[0]) str_copy(xbin, sizeof(xbin), cfg->xray_bin);
    else                  apply_find_xray(xbin, sizeof(xbin));
    json_kv_str(&j, "xray_bin", xbin);

    json_kv_str(&j, "policy_name", cfg->policy);
    json_kv_str(&j, "proxy_name", cfg->proxy_iface);
    json_kv_int(&j, "socks_port", cfg->socks_port);

    /* Есть ли политика и подключение на роутере. */
    rci_t rci;
    rci_init(&rci);

    unsigned mark = 0;
    json_kv_bool(&j, "policy_ready",
                 rci_policy_mark(&rci, cfg->policy, &mark) == 0 && mark != 0);

    char ipath[128], iout[256];
    snprintf(ipath, sizeof(ipath), "/rci/show/interface/%s", cfg->proxy_iface);
    int icode = rci_request(&rci, "GET", ipath, NULL, iout, sizeof(iout));
    json_kv_bool(&j, "proxy_ready", icode == 200 && !strstr(iout, "\"code\""));

    /* Есть ли хоть одна ссылка на сервер. */
    int have_link = 0;
    {
        static char nodes[8192];
        if (slurp(cfg->nodes_file, nodes, sizeof(nodes)) > 0)
            have_link = strstr(nodes, "://") != NULL;
    }
    json_kv_bool(&j, "have_link", have_link);

    /* Проверка DNS. Отвечаем не «да/нет», а тремя состояниями: сказать
       «устройство ходит мимо» можно только когда видно, что другие
       устройства роутер всё-таки спрашивают. Иначе это будет ложная
       тревога сразу после запуска, когда перехват ещё ничего не набрал. */
    const char *dns = "unknown";
    if (e->capturing && req->peer[0] &&
        strcmp(req->peer, "127.0.0.1") != 0 &&
        strcmp(req->peer, cfg->web_bind[0] ? cfg->web_bind : "") != 0) {

        unsigned char addr[4];
        long          now = (long)time(NULL);

        /* Страница может сказать, что только что заставила устройство
           сделать запрос. Тогда молчание — уже улика, и ждать окно не
           нужно. Без этого признака ждём: сразу после запуска «этого не
           видели» значит лишь, что мы мало смотрели. Один раз такая
           поспешность уже дала ложную тревогу. */
        char probed[8] = "";
        int  forced    = http_query_get(req, "probed", probed, sizeof(probed)) &&
                         probed[0] == '1';
        int  watched   = now - e->cap.watching_since >= DNS_CHECK_WINDOW;

        if (inet_pton(AF_INET, req->peer, addr) == 1) {
            if (dcap_seen_client(&e->cap, 4, addr, now, DNS_CHECK_WINDOW))
                dns = "ok";
            else if ((forced || watched) &&
                     dcap_client_count(&e->cap, now, DNS_CHECK_WINDOW) > 0)
                dns = "bypass";
        }
    }
    /* Модель и версия прошивки — из роутера, для подвала страницы.
       Имена полей у разных прошивок разнятся, поэтому пробуем несколько
       по очереди: пустой подвал лучше неверного, но лучше всего —
       заполненный. */
    char model[96] = "", osver[48] = "";
    {
        char out[2048] = "";
        if (rci_request(&rci, "GET", "/rci/show/version", NULL, out, sizeof(out)) == 200) {
            static const char *models[]  = { "description", "device", "model", NULL };
            static const char *versions[] = { "title", "release", "version", NULL };

            for (int i = 0; models[i] && !model[0]; i++)
                json_field(out, models[i], model, sizeof(model));
            for (int i = 0; versions[i] && !osver[0]; i++)
                json_field(out, versions[i], osver, sizeof(osver));
        }
    }
    json_kv_str(&j, "model", model);
    json_kv_str(&j, "osver", osver);

    json_kv_str(&j, "dns", dns);
    json_kv_str(&j, "peer", req->peer);

    json_key(&j, "groups");
    json_arr_open(&j);
    for (int i = 0; i < e->wl.group_count; i++) {
        const wl_group_t *g = &e->wl.groups[i];
        json_obj_open(&j);
        json_kv_str(&j, "name", g->name);
        json_kv_str(&j, "target", g->iface[0] ? g->iface : "не задан");
        json_kv_str(&j, "kind",
                    g->target == WL_TARGET_IFACE  ? "устройство" :
                    g->target == WL_TARGET_POLICY ? "политика"   : "неизвестно");
        json_kv_int(&j, "addrs", 0);
        json_obj_close(&j);
    }
    json_arr_close(&j);

    /* Списки отдаём как есть: страница их же и правит. */
    static char text[64 * 1024];
    const char *parts[] = { "domains", "cidrs", NULL };
    for (int i = 0; parts[i]; i++) {
        char path[CFG_PATH_MAX + 32];
        file_for(cfg, parts[i], path, sizeof(path));
        if (slurp(path, text, sizeof(text)) < 0) text[0] = '\0';
        json_kv_str(&j, parts[i], text);
    }

    /* Ссылки — только по отдельной просьбе. Обычное обновление страницы
       не должно таскать ключ в браузер и оставлять его в кеше. */
    char npath[CFG_PATH_MAX + 32];
    file_for(cfg, "nodes", npath, sizeof(npath));
    if (slurp(npath, text, sizeof(text)) < 0) text[0] = '\0';

    char reveal[8] = "";
    if (http_query_get(req, "reveal", reveal, sizeof(reveal)) && reveal[0] == '1') {
        json_kv_str(&j, "nodes", text);
        json_kv_bool(&j, "nodes_shown", 1);
    } else {
        static char masked[64 * 1024];
        mask_nodes(text, masked, sizeof(masked));
        json_kv_str(&j, "nodes", masked);
        json_kv_bool(&j, "nodes_shown", 0);
    }

    json_obj_close(&j);

    if (json_done(&j) != 0) {
        http_send_text(fd, 500, "text/plain; charset=utf-8",
                       "не удалось собрать ответ\n");
        return;
    }

    http_send(fd, 200, "application/json; charset=utf-8", buf, strlen(buf));
}

/* Серверы DNS роутера. Берём из его же running-config через ndmc:
   точного пути в RCI я не знаю, а выдумывать нельзя. Из вывода отбираем
   только строки про DNS — там же лежит хеш пароля администратора, и
   отдавать наружу всё подряд недопустимо. */
/* ndmc лежит в прошивке, и путь у разных моделей разный. Перебираем
   обычные места, как это уже делается для ipset и iptables. */
static const char *NDMC_CANDIDATES[] = {
    "/opt/bin/ndmc", "/opt/sbin/ndmc",
    "/usr/bin/ndmc", "/usr/sbin/ndmc",
    "/bin/ndmc",     "/sbin/ndmc",
    NULL
};

static int ndmc_path(char *dst, unsigned size)
{
    for (int i = 0; NDMC_CANDIDATES[i]; i++) {
        if (access(NDMC_CANDIDATES[i], X_OK) == 0) {
            str_copy(dst, size, NDMC_CANDIDATES[i]);
            return 1;
        }
    }
    dst[0] = '\0';
    return 0;
}

static void send_dns(int fd)
{
    char bin[192] = "";
    char arg[] = "-c";
    char cmd[] = "show running-config";

    ndmc_path(bin, sizeof(bin));

    static char out[64 * 1024];
    char *argv[] = { bin, arg, cmd, NULL };

    char buf[16 * 1024];
    json_t j;
    json_init(&j, buf, sizeof(buf));
    json_obj_open(&j);

    /* Без ndmc спрашивать нечего, и это надо сказать прямо: «не удалось
       прочитать» одинаково звучит и когда программы нет, и когда она
       ответила ошибкой — а чинится это по-разному. */
    int rc = bin[0] ? proc_run(argv, out, sizeof(out), 10) : -1;

    json_kv_bool(&j, "ok", rc == 0);
    json_kv_str(&j, "why", bin[0] ? (rc == 0 ? "" : "ndmc ответил ошибкой")
                                  : "ndmc не найден");
    json_kv_str(&j, "bin", bin);
    json_key(&j, "servers");
    json_arr_open(&j);

    /* Разбор портит текст, поэтому держим вторую копию: интерфейсы
       ищутся по нему же. */
    static char copy[64 * 1024];
    if (rc == 0) str_copy(copy, sizeof(copy), out);

    if (rc == 0) {
        const char *found[DNS_LINES_MAX];
        int n = dns_upstreams(out, found, DNS_LINES_MAX);
        for (int i = 0; i < n; i++) json_str(&j, found[i]);
    }

    json_arr_close(&j);

    /* Интерфейсы, которые ещё берут DNS у провайдера. */
    json_key(&j, "isp");
    json_arr_open(&j);
    if (rc == 0) {
        const char *ifs[DNS_LINES_MAX];
        int n = dns_isp_interfaces(copy, ifs, DNS_LINES_MAX);
        for (int i = 0; i < n; i++) json_str(&j, ifs[i]);
    }
    json_arr_close(&j);

    json_obj_close(&j);

    if (json_done(&j) != 0) {
        http_send_text(fd, 500, "text/plain; charset=utf-8", "не поместилось\n");
        return;
    }
    http_send(fd, 200, "application/json; charset=utf-8", buf, strlen(buf));
}

/* Команды взяты из running-config настоящего роутера, а не придуманы:
   серверы там записаны ровно в этой форме. Только добавление — ничего
   существующего не трогаем, и провайдерский DNS не отключаем: точной
   формы этой команды я не знаю, а угадывать то, что меняет настройки
   роутера, нельзя. */
/* Ставим и DoT, и DoH: роутер умеет оба, а форма команд взята из его
   же running-config. */
static const struct {
    const char *key;
    const char *cmds[4];
} DNS_SETS[] = {
    { "cf", {
        "dns-proxy tls upstream 1.1.1.1 sni cloudflare-dns.com",
        "dns-proxy tls upstream 1.0.0.1 sni cloudflare-dns.com",
        "dns-proxy https upstream https://cloudflare-dns.com/dns-query dnsm",
        NULL } },
    { "google", {
        "dns-proxy tls upstream 8.8.8.8 sni dns.google",
        "dns-proxy tls upstream 8.8.4.4 sni dns.google",
        "dns-proxy https upstream https://dns.google/dns-query dnsm",
        NULL } },
    { "quad9", {
        "dns-proxy tls upstream 9.9.9.9 sni dns.quad9.net",
        "dns-proxy tls upstream 149.112.112.112 sni dns.quad9.net",
        "dns-proxy https upstream https://dns.quad9.net/dns-query dnsm",
        NULL } },
    { NULL, { NULL } }
};

/* Есть ли ключ в списке через запятую. Сравниваем по границам, иначе
   «cf» нашлось бы внутри чужого слова. */
static int chosen(const char *list, const char *key)
{
    size_t klen = strlen(key);

    for (const char *p = list; *p; p++) {
        if (p != list && p[-1] != ',') continue;
        if (strncmp(p, key, klen) != 0) continue;
        if (p[klen] == '\0' || p[klen] == ',') return 1;
    }
    return 0;
}

static void apply_dns(const http_req_t *req, int fd)
{
    char bin[192] = "";
    if (!ndmc_path(bin, sizeof(bin))) {
        http_send_text(fd, 500, "text/plain; charset=utf-8",
                       "ndmc не найден, настройки роутера не тронуты\n");
        return;
    }

    char sets[128] = "";
    http_query_get(req, "sets", sets, sizeof(sets));
    if (!sets[0]) {
        http_send_text(fd, 400, "text/plain; charset=utf-8",
                       "не выбрано ни одного набора\n");
        return;
    }

    /* Собираем список выбранного, а в конце — включение службы и
       сохранение конфигурации, иначе после перезагрузки всё пропадёт. */
    const char *plan[40];
    int         count = 0;

    for (int i = 0; DNS_SETS[i].key && count < 14; i++) {
        if (!chosen(sets, DNS_SETS[i].key)) continue;
        for (int k = 0; DNS_SETS[i].cmds[k]; k++) plan[count++] = DNS_SETS[i].cmds[k];
    }

    char isp_early[8] = "";
    http_query_get(req, "isp", isp_early, sizeof(isp_early));
    if (!count && isp_early[0] != '1') {
        http_send_text(fd, 400, "text/plain; charset=utf-8",
                       "выбранных наборов нет\n");
        return;
    }

    /* Отключение провайдерского DNS: команды берём из running-config,
       он печатает ровно то, чем конфигурация воспроизводится. Трогаем
       только те интерфейсы, где это ещё включено. */
    static char ifcmds[DNS_LINES_MAX][96];
    int         ifn = 0;

    char isp[8] = "";
    http_query_get(req, "isp", isp, sizeof(isp));

    if (isp[0] == '1') {
        char arg[] = "-c";
        char show[] = "show running-config";
        char *sargv[] = { bin, arg, show, NULL };
        static char cfgtext[64 * 1024];

        if (proc_run(sargv, cfgtext, sizeof(cfgtext), 10) == 0) {
            const char *ifs[DNS_LINES_MAX];
            int n = dns_isp_interfaces(cfgtext, ifs, DNS_LINES_MAX);

            for (int i = 0; i < n && ifn + 2 < DNS_LINES_MAX && count < 36; i++) {
                snprintf(ifcmds[ifn], sizeof(ifcmds[ifn]),
                         "interface %s ip no name-servers", ifs[i]);
                plan[count++] = ifcmds[ifn++];
                snprintf(ifcmds[ifn], sizeof(ifcmds[ifn]),
                         "interface %s ipv6 no name-servers", ifs[i]);
                plan[count++] = ifcmds[ifn++];
            }
        }
    }

    plan[count++] = "service dns-proxy";
    plan[count++] = "system configuration save";

    static char report[8 * 1024];
    int  used = 0, failed = 0;

    for (int i = 0; i < count; i++) {
        char arg[] = "-c";
        char cmd[128];
        str_copy(cmd, sizeof(cmd), plan[i]);

        char *argv[] = { bin, arg, cmd, NULL };
        char  out[512] = "";
        int   rc = proc_run(argv, out, sizeof(out), 15);

        if (rc != 0) failed++;
        log_info("веб: ndmc «%s» -> %d", plan[i], rc);

        int n = snprintf(report + used, sizeof(report) - (size_t)used,
                         "%s %s\n", rc == 0 ? "ok " : "СБОЙ", plan[i]);
        if (n < 0 || (size_t)n >= sizeof(report) - (size_t)used) break;
        used += n;
    }

    log_info("веб: серверы DNS установлены, сбоев %d, запрос с %s",
             failed, req->peer);

    http_send(fd, failed ? 500 : 200, "text/plain; charset=utf-8",
              report, strlen(report));
}

/* Политика доступа целиком: создать, разрешить своё подключение и
   запретить остальные. Форма команд взята из running-config роутера —
   там политики записаны ровно так. Список интерфейсов тоже берём у
   него: он зависит от того, что настроено, и выдумывать его нельзя. */
static void apply_policy(const http_req_t *req, int fd, const config_t *cfg)
{
    char bin[192] = "";
    if (!ndmc_path(bin, sizeof(bin))) {
        http_send_text(fd, 500, "text/plain; charset=utf-8",
                       "ndmc не найден, настройки роутера не тронуты\n");
        return;
    }

    char arg[] = "-c";

    /* Что вообще есть, между чем выбирать. */
    static char cfgtext[64 * 1024];
    char        show[] = "show running-config";
    char       *sargv[] = { bin, arg, show, NULL };

    const char *globals[DNS_LINES_MAX];
    int         gn = 0;

    if (proc_run(sargv, cfgtext, sizeof(cfgtext), 10) == 0)
        gn = policy_globals(cfgtext, globals, DNS_LINES_MAX);

    static char cmds[DNS_LINES_MAX + 4][160];
    int         n = 0;

    snprintf(cmds[n++], sizeof(cmds[0]), "ip policy %s", cfg->policy);
    snprintf(cmds[n++], sizeof(cmds[0]), "ip policy %s permit global %s",
             cfg->policy, cfg->proxy_iface);

    for (int i = 0; i < gn && n < DNS_LINES_MAX + 2; i++) {
        if (!strcmp(globals[i], cfg->proxy_iface)) continue;
        snprintf(cmds[n++], sizeof(cmds[0]), "ip policy %s no permit global %s",
                 cfg->policy, globals[i]);
    }

    snprintf(cmds[n++], sizeof(cmds[0]), "system configuration save");

    static char report[4 * 1024];
    int used = 0, failed = 0;

    for (int i = 0; i < n; i++) {
        char  cmd[160];
        str_copy(cmd, sizeof(cmd), cmds[i]);
        char *argv[] = { bin, arg, cmd, NULL };
        char  out[512] = "";

        int rc = proc_run(argv, out, sizeof(out), 15);
        if (rc != 0) failed++;
        log_info("веб: ndmc «%s» -> %d", cmds[i], rc);

        int k = snprintf(report + used, sizeof(report) - (size_t)used,
                         "%s %s\n", rc == 0 ? "ok " : "СБОЙ", cmds[i]);
        if (k < 0 || (size_t)k >= sizeof(report) - (size_t)used) break;
        used += k;
    }

    log_info("веб: политика %s настроена, сбоев %d, запрос с %s",
             cfg->policy, failed, req->peer);

    http_send(fd, failed ? 500 : 200, "text/plain; charset=utf-8",
              report, strlen(report));
}

/* ---- обновление пакета ---- */

static const char *OPKG_CANDIDATES[] = {
    "/opt/bin/opkg", "/opt/sbin/opkg", "/bin/opkg", "/usr/bin/opkg", NULL
};

static int opkg_path(char *dst, unsigned size)
{
    for (int i = 0; OPKG_CANDIDATES[i]; i++) {
        if (access(OPKG_CANDIDATES[i], X_OK) == 0) {
            str_copy(dst, size, OPKG_CANDIDATES[i]);
            return 1;
        }
    }
    dst[0] = '\0';
    return 0;
}

/* Запуск, переживающий смерть родителя. Обновление снимает демона
   своим же prerm, поэтому обычный дочерний процесс погиб бы вместе с
   ним на середине замены файлов. Двойной fork с setsid отвязывает
   работу от нас; ответ странице уходит сразу. */
static int spawn_detached(const char *command)
{
    pid_t first = fork();
    if (first < 0) return -1;

    if (first == 0) {
        if (setsid() < 0) _exit(1);

        pid_t second = fork();
        if (second < 0) _exit(1);
        if (second > 0) _exit(0);       /* родителя ждёт наш вызывающий */

        for (int fdn = 0; fdn < 3; fdn++) close(fdn);
        open("/dev/null", O_RDWR);
        if (dup(0) < 0 || dup(0) < 0) _exit(1);

        execl("/bin/sh", "sh", "-c", command, (char *)NULL);
        _exit(127);
    }

    int st = 0;
    waitpid(first, &st, 0);            /* короткий: он сразу форкается и выходит */
    return 0;
}

#define UPDATE_LOG "/opt/var/log/shadowfox-update.log"

static void check_update(int fd)
{
    char bin[192] = "";
    char buf[2048];
    json_t j;

    json_init(&j, buf, sizeof(buf));
    json_obj_open(&j);
    json_kv_str(&j, "current", VERSION);

    if (!opkg_path(bin, sizeof(bin))) {
        json_kv_bool(&j, "ok", 0);
        json_kv_str(&j, "why", "opkg не найден");
        json_kv_str(&j, "available", "");
        json_obj_close(&j);
        if (json_done(&j) == 0)
            http_send(fd, 200, "application/json; charset=utf-8", buf, strlen(buf));
        return;
    }

    static char out[16 * 1024];
    char upd[] = "update";
    char *uargv[] = { bin, upd, NULL };
    proc_run(uargv, out, sizeof(out), 60);

    char lst[] = "list-upgradable";
    char *largv[] = { bin, lst, NULL };
    int rc = proc_run(largv, out, sizeof(out), 30);

    char available[64] = "";
    if (rc == 0) {
        for (char *line = strtok(out, "\n"); line; line = strtok(NULL, "\n")) {
            char *t = str_trim(line);
            if (strncmp(t, "shadowfox ", 10) != 0) continue;

            /* Формат: «shadowfox - старая - новая». Берём последнее поле. */
            char *last = strrchr(t, ' ');
            if (last) str_copy(available, sizeof(available), last + 1);
            break;
        }
    }

    json_kv_bool(&j, "ok", rc == 0);
    json_kv_str(&j, "why", rc == 0 ? "" : "opkg ответил ошибкой");
    json_kv_str(&j, "available", available);
    json_obj_close(&j);

    if (json_done(&j) != 0) {
        http_send_text(fd, 500, "text/plain; charset=utf-8", "не поместилось\n");
        return;
    }
    http_send(fd, 200, "application/json; charset=utf-8", buf, strlen(buf));
}

static void do_update(const http_req_t *req, int fd)
{
    char bin[192] = "";
    if (!opkg_path(bin, sizeof(bin))) {
        http_send_text(fd, 500, "text/plain; charset=utf-8", "opkg не найден\n");
        return;
    }

    char command[512];
    snprintf(command, sizeof(command),
             "sleep 1; { date; %s update; %s upgrade shadowfox; date; } > %s 2>&1",
             bin, bin, UPDATE_LOG);

    if (spawn_detached(command) != 0) {
        http_send_text(fd, 500, "text/plain; charset=utf-8", "не запустить\n");
        return;
    }

    log_info("веб: запущено обновление пакета, запрос с %s", req->peer);
    http_send_text(fd, 200, "text/plain; charset=utf-8",
                   "обновление запущено\n");
}

static void save(const http_req_t *req, int fd, const config_t *cfg)
{
    char what[32];
    if (!http_query_get(req, "what", what, sizeof(what))) {
        http_send_text(fd, 400, "text/plain; charset=utf-8", "не сказано что\n");
        return;
    }

    char path[CFG_PATH_MAX + 32];
    if (!file_for(cfg, what, path, sizeof(path))) {
        http_send_text(fd, 400, "text/plain; charset=utf-8", "неизвестный раздел\n");
        return;
    }

    /* Списки перезаписываем целиком, поэтому неполное тело обязано быть
       отказом, а не усечённым файлом: один раз это уже стёрло домены. */
    if (req->declared_len >= 0 && (size_t)req->declared_len != req->body_len) {
        log_warn("веб: тело %zu из %ld — %s не трогаю",
                 req->body_len, req->declared_len, path);
        http_send_text(fd, 400, "text/plain; charset=utf-8",
                       "запрос пришёл не целиком, ничего не изменено\n");
        return;
    }

    /* Замаскированный текст сохранять нельзя: так ключ был бы затёрт
       точками. Проверяем на сервере, а не только на странице — цена
       ошибки тут потеря доступа к серверу. */
    if (!strcmp(what, "nodes") && req->body_len &&
        memmem(req->body, req->body_len, MASK_MARK, strlen(MASK_MARK))) {
        http_send_text(fd, 400, "text/plain; charset=utf-8",
                       "это скрытый вид ссылок, а не они сами — нажми «Показать»\n");
        return;
    }

    /* Пишем во временный файл и переименовываем: демон может читать
       этот же файл в этот самый момент. */
    char tmp[CFG_PATH_MAX + 40];
    snprintf(tmp, sizeof(tmp), "%s.web", path);

    FILE *f = fopen(tmp, "w");
    if (!f) {
        http_send_text(fd, 500, "text/plain; charset=utf-8", "не создать файл\n");
        return;
    }

    if (req->body && req->body_len)
        fwrite(req->body, 1, req->body_len, f);

    int bad = ferror(f);
    fclose(f);

    if (bad || rename(tmp, path) != 0) {
        unlink(tmp);
        http_send_text(fd, 500, "text/plain; charset=utf-8", "не записать\n");
        return;
    }

    /* В ссылках лежит uuid — посторонним читать незачем. */
    if (!strcmp(what, "nodes")) chmod(path, 0600);

    log_info("веб: сохранён %s", path);

    /* Перечитывание делает главный цикл: трогать движок из обработчика
       запроса значит менять правила посреди чужой работы. */
    kill(getpid(), SIGHUP);

    http_send_text(fd, 200, "text/plain; charset=utf-8", "сохранено, применяю\n");
}

/* ---------- Сессии ---------- */

/* Вход проверяется паролем от роутера: своего пароля мы не заводим,
   чтобы не появилось второго секрета, который надо где-то хранить и
   потом восстанавливать. Успешная проверка выдаёт случайную метку
   сессии; сам пароль нигде не сохраняется. */

#define SESSIONS_MAX   8
#define SESSION_HOURS  12

static struct {
    char token[41];
    long until;
} g_sessions[SESSIONS_MAX];

static void session_new(char *out, unsigned out_size)
{
    unsigned char raw[20];
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f || fread(raw, 1, sizeof(raw), f) != sizeof(raw)) {
        /* Предсказуемая метка пустила бы посторонних, поэтому лучше
           не выдать никакой. */
        if (f) fclose(f);
        out[0] = '\0';
        return;
    }
    fclose(f);

    char hex[41];
    hex_encode(raw, sizeof(raw), hex);
    str_copy(out, out_size, hex);

    long now  = (long)time(NULL);
    int  slot = 0;
    for (int i = 0; i < SESSIONS_MAX; i++) {
        if (g_sessions[i].until <= now) { slot = i; break; }
        if (g_sessions[i].until < g_sessions[slot].until) slot = i;
    }

    str_copy(g_sessions[slot].token, sizeof(g_sessions[slot].token), hex);
    g_sessions[slot].until = now + SESSION_HOURS * 3600;
}

static int cookie_value(const http_req_t *req, const char *name,
                        char *out, unsigned out_size)
{
    out[0] = '\0';
    if (!req->cookie || !req->cookie_len) return 0;

    const char *c    = req->cookie;
    const char *end  = c + req->cookie_len;
    size_t      nlen = strlen(name);

    for (const char *p = c; p + nlen < end; p++) {
        if (p != c && !(p[-1] == ' ' || p[-1] == ';')) continue;
        if (strncmp(p, name, nlen) != 0 || p[nlen] != '=') continue;

        const char *v = p + nlen + 1;
        unsigned    i = 0;
        while (v < end && *v != ';' && i + 1 < out_size) { out[i++] = *v++; }
        out[i] = '\0';
        return i > 0;
    }
    return 0;
}

static int session_valid(const http_req_t *req)
{
    char tok[64] = "";
    if (!cookie_value(req, "sfsession", tok, sizeof(tok))) return 0;

    long now = (long)time(NULL);
    for (int i = 0; i < SESSIONS_MAX; i++) {
        if (g_sessions[i].until <= now) continue;
        if (!strcmp(g_sessions[i].token, tok)) return 1;
    }
    return 0;
}

static void session_drop(const http_req_t *req)
{
    char tok[64] = "";
    if (!cookie_value(req, "sfsession", tok, sizeof(tok))) return;

    for (int i = 0; i < SESSIONS_MAX; i++)
        if (!strcmp(g_sessions[i].token, tok)) g_sessions[i].until = 0;
}

/* Значение поля из тела формы. Тело короткое и своё, поэтому разбор
   простой; проценты раскрываем, плюс считаем пробелом. */
static void form_field(const char *body, size_t len, const char *name,
                       char *out, unsigned out_size)
{
    out[0] = '\0';
    if (!body) return;

    size_t nlen = strlen(name);
    for (size_t i = 0; i + nlen + 1 <= len; i++) {
        if (i && body[i - 1] != '&') continue;
        if (strncmp(body + i, name, nlen) != 0 || body[i + nlen] != '=') continue;

        size_t   v = i + nlen + 1;
        unsigned o = 0;
        while (v < len && body[v] != '&' && o + 1 < out_size) {
            if (body[v] == '+') { out[o++] = ' '; v++; }
            else if (body[v] == '%' && v + 2 < len) {
                char h[3] = { body[v+1], body[v+2], '\0' };
                out[o++] = (char)strtol(h, NULL, 16);
                v += 3;
            } else out[o++] = body[v++];
        }
        out[o] = '\0';
        return;
    }
}

static void send_login(int fd, const char *message)
{
    static char page[4096];
    snprintf(page, sizeof(page),
        "<!doctype html><meta charset=utf-8>"
        "<meta name=viewport content=\"width=device-width,initial-scale=1\">"
        "<title>Shadow Fox</title><style>"
        ":root{color-scheme:dark light}"
        "@font-face{font-family:Cinzel;font-weight:600;font-display:swap;"
        "src:url(/cinzel.woff2) format('woff2')}"
        "body{margin:0;min-height:100vh;display:grid;place-items:center;"
        "background:#0d1014;color:#e8ecf2;"
        "font:14px/1.55 system-ui,-apple-system,'Segoe UI',Roboto,sans-serif}"
        "form{background:#151a21;border:1px solid #28303b;border-radius:16px;"
        "padding:28px 30px 26px;width:min(400px,92vw)}"
        "img{display:block;margin:0 auto 6px;max-width:60%%;height:auto}"
        "h1{margin:0 0 4px;text-align:center;color:#22c8e6;"
        "font:600 26px/1.1 Cinzel,'Times New Roman',Georgia,serif;"
        "letter-spacing:.03em}"
        "p{margin:0 0 18px;color:#8b95a5;font-size:13px;text-align:center}"
        "label{display:block;color:#8b95a5;font-size:12.5px;margin:12px 0 5px}"
        "input{width:100%%;box-sizing:border-box;background:#0d1014;color:#e8ecf2;"
        "border:1px solid #28303b;border-radius:7px;padding:10px;font:14px/1.4 inherit}"
        "button{width:100%%;margin-top:20px;background:#22b8d6;color:#04222a;border:0;"
        "border-radius:8px;padding:11px;font:650 14px/1 inherit;cursor:pointer}"
        ".bad{color:#ff6b6b;font-size:13px;margin-top:14px}"
        "</style>"
        "<form method=post action=/login>"
        "<img src=/logo.png alt=\"\" width=168 height=168>"
        "<h1>Shadow Fox</h1>"
        "<p>Логин и пароль администратора роутера</p>"
        "<label>Логин</label><input name=login autofocus autocomplete=username>"
        "<label>Пароль</label>"
        "<input name=password type=password autocomplete=current-password>"
        "<button>Войти</button>"
        "%s%s%s</form>",
        message && *message ? "<div class=bad>" : "",
        message && *message ? message : "",
        message && *message ? "</div>" : "");

    http_send(fd, 200, "text/html; charset=utf-8", page, strlen(page));
}

/* Свой ограничитель попыток. У роутера есть защита от перебора, и она
   заносит в чёрный список адрес, с которого идут попытки, — а идут они
   с самого роутера. Дойдя до его порога, мы закрываем себе не только
   вход в Shadow Fox, но и обычный вход в роутер с этого адреса. Поэтому
   останавливаемся раньше, чем он. */
#define LOGIN_TRIES     3
#define LOGIN_COOLDOWN  60

static int  g_bad_tries;
static long g_bad_until;

static void do_login(const http_req_t *req, int fd, const config_t *cfg)
{
    long now = (long)time(NULL);

    if (g_bad_until > now) {
        char msg[128];
        snprintf(msg, sizeof(msg),
                 "Слишком много неудачных попыток. Подожди %ld секунд — "
                 "иначе роутер заблокирует адрес сам",
                 g_bad_until - now);
        send_login(fd, msg);
        return;
    }

    char login[128] = "", password[128] = "";
    form_field(req->body, req->body_len, "login", login, sizeof(login));
    form_field(req->body, req->body_len, "password", password, sizeof(password));

    if (!login[0]) { send_login(fd, "Введи логин"); return; }

    /* Спрашивать роутер надо с адреса сети, а не с петли: на 127.0.0.1
       он отвечает «insufficient security level» и заголовков схемы не
       присылает вовсе. */
    char host[64] = "";
    if (cfg->router_host[0])
        str_copy(host, sizeof(host), cfg->router_host);
    else if (!iface_ipv4(cfg->capture_iface, host, sizeof(host))) {
        send_login(fd, "не узнать адрес роутера, задай routerHost");
        return;
    }

    char         err[160] = "";
    ndm_result_t r = ndm_check_password(host, cfg->router_port,
                                        login, password, err, sizeof(err));

    /* Пароль в памяти не задерживаем дольше нужного. */
    memset(password, 0, sizeof(password));

    if (r != NDM_OK) {
        if (r == NDM_DENIED && ++g_bad_tries >= LOGIN_TRIES) {
            g_bad_tries = 0;
            g_bad_until = now + LOGIN_COOLDOWN;
        }
        log_warn("веб: вход отклонён (%s), запрос с %s",
                 err[0] ? err : "не подошло", req->peer);
        send_login(fd, err[0] ? err : "Неверный логин или пароль");
        return;
    }

    g_bad_tries = 0;
    g_bad_until = 0;

    char tok[64];
    session_new(tok, sizeof(tok));
    if (!tok[0]) { send_login(fd, "Не удалось создать сессию"); return; }

    log_info("веб: вход выполнен, запрос с %s", req->peer);

    char head[256];
    snprintf(head, sizeof(head),
             "Set-Cookie: sfsession=%s; Path=/; HttpOnly; SameSite=Strict; Max-Age=%d",
             tok, SESSION_HOURS * 3600);
    http_send_with(fd, 303, "text/plain; charset=utf-8", head, "Location: /", "", 0);
}

static void handle(const http_req_t *req, int fd, void *ctx)
{
    webctx_t *c = ctx;

    if (!strcmp(req->path, "/cinzel.woff2")) {
        http_send_gzip(fd, "font/woff2", web_font, web_font_len);
        return;
    }

    if (!strcmp(req->path, "/logo.png")) {
        /* Без проверки входа: картинка нужна самой форме входа, а тайны
           в ней нет. */
        http_send_gzip(fd, "image/png", web_logo, web_logo_len);
        return;
    }

    if (!strcmp(req->path, "/login") && !strcmp(req->method, "POST")) {
        do_login(req, fd, c->cfg);
        return;
    }

    /* Заданный токен остаётся запасным входом: если проверка пароля на
       какой-то прошивке не сработает, доступ к интерфейсу не потеряется.
       По умолчанию он пуст, и тогда единственный путь — пароль роутера. */
    /* Запасной токен принимаем и заголовком, и в строке запроса: по
       ссылке им пользоваться проще, а именно ради простоты он и нужен —
       это путь на случай, если проверка пароля почему-то не работает. */
    int allowed = session_valid(req);

    if (!allowed && c->cfg->web_token[0]) {
        char q[64] = "";
        http_query_get(req, "token", q, sizeof(q));
        allowed = !strcmp(c->cfg->web_token, req->token) ||
                  (q[0] && !strcmp(c->cfg->web_token, q));
    }

    if (!strcmp(req->path, "/logout")) {
        session_drop(req);
        http_send_with(fd, 303, "text/plain; charset=utf-8",
                       "Set-Cookie: sfsession=; Path=/; Max-Age=0",
                       "Location: /", "", 0);
        return;
    }

    if (!allowed) {
        /* Страницу подменяем формой входа, а данным отвечаем отказом:
           иначе страница показала бы форму внутри себя. */
        if (!strcmp(req->path, "/") || !strcmp(req->path, "/index.html"))
            send_login(fd, "");
        else
            http_send_text(fd, 401, "text/plain; charset=utf-8", "нужен вход\n");
        return;
    }

    if (!strcmp(req->path, "/") || !strcmp(req->path, "/index.html")) {
        http_send_gzip(fd, "text/html; charset=utf-8", web_page, web_page_len);
        return;
    }

    if (!strcmp(req->path, "/data")) {
        send_data(req, fd, c->engine, c->cfg);
        return;
    }

    if (!strcmp(req->path, "/update")) {
        if (!strcmp(req->method, "POST")) do_update(req, fd);
        else                              check_update(fd);
        return;
    }

    if (!strcmp(req->path, "/policy") && !strcmp(req->method, "POST")) {
        apply_policy(req, fd, c->cfg);
        return;
    }

    if (!strcmp(req->path, "/dns")) {
        if (!strcmp(req->method, "POST")) apply_dns(req, fd);
        else                              send_dns(fd);
        return;
    }

    if (!strcmp(req->path, "/save") && !strcmp(req->method, "POST")) {
        save(req, fd, c->cfg);
        return;
    }

    http_send_text(fd, 404, "text/plain; charset=utf-8", "нет такой страницы\n");
}

void webui_poll(http_t *h, struct engine *e, const config_t *cfg)
{
    webctx_t ctx = { e, cfg };
    http_poll(h, handle, &ctx);
}
