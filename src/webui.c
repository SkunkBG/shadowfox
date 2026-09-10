#include "webui.h"

#include "digest.h"
#include "ndmauth.h"
#include "proc.h"
#include "mask.h"
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
#include "shadowfox.h"
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
extern const unsigned char web_loginjs[];
extern const size_t        web_loginjs_len;

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

    /* Закрываем прежний сокет до http_init: тот обнуляет структуру, и
       живой дескриптор потерялся бы, оставшись открытым в ядре. */
    http_close(h);
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

/* Кеш ответов роутера для /data; сбрасывается кнопками, которые меняют
   политику или подключение, — иначе карточка не позеленела бы до минуты. */
static time_t g_rci_at;
static int    g_rci_policy, g_rci_proxy;
static char   g_rci_model[96], g_rci_osver[48];

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
    json_kv_int(&j, "tunnel", e->tunnel_state);
    json_kv_int(&j, "tunnel_since", (long)e->tunnel_since);
    json_kv_int(&j, "tunnel_est", e->tunnel_established);
    json_kv_int(&j, "tunnel_pending", e->tunnel_pending);
    json_kv_str(&j, "tunnel_why", e->tunnel_why);
    json_kv_bool(&j, "capture", e->capturing);
    json_kv_str(&j, "iface", cfg->capture_iface);
    json_kv_int(&j, "seen", (long)e->cap.seen);
    json_kv_int(&j, "parsed", (long)e->cap.parsed);
    json_kv_int(&j, "matched", (long)e->matched);
    json_kv_bool(&j, "rules", e->rules_applied);
    json_kv_int(&j, "marked", (long)e->marked_conns);
    json_kv_int(&j, "restored", (long)e->restored_pkts);
    json_kv_bool(&j, "sni_on", e->sniffing);
    json_kv_int(&j, "sni_names", (long)e->sni_names);
    json_kv_int(&j, "sni_new", (long)e->sni_new);
    json_kv_int(&j, "sni_broken", (long)e->sni_broken);
    json_kv_int(&j, "sni_throttled", (long)e->sni_throttled);

    /* Что уже сделано, а что нет: без этого со страницы непонятно,
       какой шаг настройки следующий. */
    char xbin[APPLY_PATH_MAX] = "";
    if (cfg->xray_bin[0]) str_copy(xbin, sizeof(xbin), cfg->xray_bin);
    else                  apply_find_xray(xbin, sizeof(xbin));
    json_kv_str(&j, "xray_bin", xbin);
    json_kv_str(&j, "xray_version", e->xray_version);

    /* Журнал ошибок ядра: число и последняя строка. Адреса в ней ядро
       уже маскирует само (maskAddress). */
    {
        char last[200];
        long lines = 0;
        file_tail(XRAY_ERROR_LOG, last, sizeof(last), &lines);
        json_kv_int(&j, "xray_errors", (int)(lines > 1000000 ? 1000000 : lines));
        json_kv_str(&j, "xray_last_error", last);
        json_kv_str(&j, "xray_error_log", XRAY_ERROR_LOG);
    }

    json_kv_bool(&j, "fragment", cfg->fragment);
    json_kv_str(&j, "fingerprint", cfg->fingerprint);

    json_kv_str(&j, "policy_name", cfg->policy);
    json_kv_str(&j, "proxy_name", cfg->proxy_iface);
    json_kv_int(&j, "socks_port", cfg->socks_port);

    /* Есть ли политика и подключение на роутере. */
    /* Обращения к роутеру — не на каждый опрос страницы. Страница
       спрашивает каждые десять секунд, а каждое обращение к RCI — это
       соединение с таймаутом в пять секунд; при занятом ndm один опрос
       держал демон до пятнадцати секунд. Готовность политики и
       подключения освежаем раз в минуту, модель и прошивку — один раз. */
    time_t t_now = time(NULL);
    if (t_now - g_rci_at >= 60) {
        g_rci_at = t_now;

        rci_t rci;
        rci_init(&rci);

        unsigned mark = 0;
        g_rci_policy = rci_policy_mark(&rci, cfg->policy, &mark) == 0 && mark != 0;

        char ipath[128], iout[256];
        snprintf(ipath, sizeof(ipath), "/rci/show/interface/%s", cfg->proxy_iface);
        int icode = rci_request(&rci, "GET", ipath, NULL, iout, sizeof(iout));
        g_rci_proxy = icode == 200 && !strstr(iout, "\"code\"");

        if (!g_rci_model[0]) {
            char out[2048] = "";
            if (rci_request(&rci, "GET", "/rci/show/version", NULL, out, sizeof(out)) == 200) {
                static const char *models[]   = { "description", "device", "model", NULL };
                static const char *versions[] = { "title", "release", "version", NULL };
                for (int i = 0; models[i] && !g_rci_model[0]; i++)
                    json_field(out, models[i], g_rci_model, sizeof(g_rci_model));
                for (int i = 0; versions[i] && !g_rci_osver[0]; i++)
                    json_field(out, versions[i], g_rci_osver, sizeof(g_rci_osver));
            }
        }
    }

    json_kv_bool(&j, "policy_ready", g_rci_policy);
    json_kv_bool(&j, "proxy_ready", g_rci_proxy);

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
    json_kv_str(&j, "model", g_rci_model);
    json_kv_str(&j, "osver", g_rci_osver);

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
        json_kv_int(&j, "addrs4", (long)e->addr4[i]);
        json_kv_int(&j, "addrs6", (long)e->addr6[i]);
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

static void send_dns(int fd, const config_t *cfg)
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
    int trunc = 0;
    int rc = bin[0] ? proc_run_capture(argv, out, sizeof(out), 10, &trunc) : -1;
    if (rc == 0 && trunc) rc = -2;

    json_kv_bool(&j, "ok", rc == 0);
    json_kv_str(&j, "why", !bin[0]   ? "ndmc не найден"
                         : rc == 0   ? ""
                         : rc == -2  ? "конфигурация роутера не поместилась в буфер"
                                     : "ndmc ответил ошибкой");
    json_kv_str(&j, "bin", bin);

    /* Спрашиваем до разбора остального: соседи режут текст на месте. */
    json_kv_bool(&j, "web", rc == 0 && http_proxy_present(out, cfg->web_proxy));
    json_kv_str(&j, "web_name", cfg->web_proxy);
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

    /* Куда вообще можно заворачивать: политики и подключения роутера.
       Раньше цель правила набиралась в prompt() руками, с опечатками, —
       а роутер эти имена знает. Третья копия конфига нужна по той же
       причине, что и вторая: разборщики режут текст на месте. */
    json_key(&j, "targets");
    json_arr_open(&j);
    if (rc == 0) {
        static char copy2[64 * 1024];
        str_copy(copy2, sizeof(copy2), copy);

        const char *pol[DNS_LINES_MAX];
        int pn = policy_names(copy2, pol, DNS_LINES_MAX);
        for (int i = 0; i < pn; i++) json_str(&j, pol[i]);

        str_copy(copy2, sizeof(copy2), copy);
        const char *gl[DNS_LINES_MAX];
        int gn2 = policy_globals(copy2, gl, DNS_LINES_MAX);
        for (int i = 0; i < gn2; i++) json_str(&j, gl[i]);
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

/* Прогон списка команд через ndmc. Три места делают одно и то же:
   выполнить по очереди, записать каждую в журнал и вернуть отчёт
   строками «ok» и «СБОЙ» — по нему на странице видно, какая именно
   команда не прошла, а не просто «не получилось». */
static void ndmc_run_plan(char *bin, const char **plan, int n,
                          const char *what, const char *peer, int fd)
{
    static char report[8 * 1024];
    int used = 0, failed = 0;

    for (int i = 0; i < n; i++) {
        char arg[] = "-c";
        char cmd[192];
        str_copy(cmd, sizeof(cmd), plan[i]);

        char *argv[] = { bin, arg, cmd, NULL };
        char  out[512] = "";
        int   rc = proc_run(argv, out, sizeof(out), 15);

        if (rc != 0) failed++;

        /* Пароль подключения ни в журнал, ни на страницу. */
        char shown[192];
        str_copy(shown, sizeof(shown), plan[i]);
        char *pw = strstr(shown, "authentication password ");
        if (pw) str_copy(pw + 24, sizeof(shown) - (size_t)(pw + 24 - shown), "****");

        log_info("веб: ndmc «%s» -> %d", shown, rc);

        int k = snprintf(report + used, sizeof(report) - (size_t)used,
                         "%s %s\n", rc == 0 ? "ok " : "СБОЙ", shown);
        if (k < 0 || (size_t)k >= sizeof(report) - (size_t)used) break;
        used += k;
    }

    log_info("веб: %s, сбоев %d, запрос с %s", what, failed, peer);
    g_rci_at = 0;   /* настройки роутера менялись — страница переспросит */

    http_send(fd, failed ? 500 : 200, "text/plain; charset=utf-8",
              report, strlen(report));
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

        int trunc = 0;
        if (proc_run_capture(sargv, cfgtext, sizeof(cfgtext), 10, &trunc) != 0 || trunc) {
            http_send_text(fd, 500, "text/plain; charset=utf-8",
                           "не удалось прочитать конфигурацию роутера, DNS не тронут\n");
            return;
        }
        {
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

    ndmc_run_plan(bin, plan, count, "серверы DNS установлены", req->peer, fd);
}

/* Публикация интерфейса на поддомене доменного имени Keenetic.

   HTTPS и проверку пароля делает сам роутер: свой вход у нас есть, но
   выставлять его наружу незачем, когда рядом есть штатный. Форма команд
   взята из running-config рабочей настройки. */
static void apply_web(const http_req_t *req, int fd, const config_t *cfg)
{
    char bin[192] = "";
    if (!ndmc_path(bin, sizeof(bin))) {
        http_send_text(fd, 500, "text/plain; charset=utf-8",
                       "ndmc не найден, настройки роутера не тронуты\n");
        return;
    }

    char lan[64] = "";
    if (cfg->web_bind[0]) {
        str_copy(lan, sizeof(lan), cfg->web_bind);
    } else if (!iface_ipv4(cfg->capture_iface, lan, sizeof(lan))) {
        char msg[192];
        snprintf(msg, sizeof(msg),
                 "не узнать адрес роутера на %s — публикация не сделана\n",
                 cfg->capture_iface);
        http_send_text(fd, 500, "text/plain; charset=utf-8", msg);
        return;
    }

    static char cmds[7][160];
    const char *plan[7];
    int n = 0;

    snprintf(cmds[n++], sizeof(cmds[0]), "ip http proxy %s", cfg->web_proxy);
    snprintf(cmds[n++], sizeof(cmds[0]), "ip http proxy %s upstream http %s %d",
             cfg->web_proxy, lan, cfg->web_port);
    snprintf(cmds[n++], sizeof(cmds[0]), "ip http proxy %s domain ndns",
             cfg->web_proxy);
    snprintf(cmds[n++], sizeof(cmds[0]), "ip http proxy %s ssl redirect",
             cfg->web_proxy);
    snprintf(cmds[n++], sizeof(cmds[0]), "ip http proxy %s security-level public",
             cfg->web_proxy);
    snprintf(cmds[n++], sizeof(cmds[0]), "ip http proxy %s auth", cfg->web_proxy);
    snprintf(cmds[n++], sizeof(cmds[0]), "system configuration save");

    for (int i = 0; i < n; i++) plan[i] = cmds[i];

    char what[160];
    snprintf(what, sizeof(what), "интерфейс опубликован как %s", cfg->web_proxy);
    ndmc_run_plan(bin, plan, n, what, req->peer, fd);
}

/* Своё подключение на роутере: прокси-клиент SOCKS5, смотрящий в наше
   ядро. Форма команд взята из running-config рабочей настройки — там
   подключение записано ровно так.

   Адрес берём с интерфейса локальной сети, а не подставляем 127.0.0.1:
   прокси-клиент Keenetic ходит на LAN-адрес роутера, на петлю он не
   пойдёт. Порт — тот же, что слушает ядро. */
static void apply_proxy(const http_req_t *req, int fd, const config_t *cfg)
{
    char bin[192] = "";
    if (!ndmc_path(bin, sizeof(bin))) {
        http_send_text(fd, 500, "text/plain; charset=utf-8",
                       "ndmc не найден, настройки роутера не тронуты\n");
        return;
    }

    char lan[64] = "";
    if (!iface_ipv4(cfg->capture_iface, lan, sizeof(lan))) {
        char msg[192];
        snprintf(msg, sizeof(msg),
                 "не узнать адрес роутера на %s — подключение не создано\n",
                 cfg->capture_iface);
        http_send_text(fd, 500, "text/plain; charset=utf-8", msg);
        return;
    }

    static char cmds[11][160];
    const char *plan[11];
    int n = 0;

    /* Пароль тот же, что у ядра: файл общий. Если демон его ещё не
       создал, создаём здесь — ядро подхватит при следующем запуске. */
    char secret[64] = "";
    if (cfg->socks_secret[0] &&
        !secret_load_or_create(cfg->socks_secret, secret, sizeof(secret)))
        log_warn("не прочитать %s — подключение без пароля", cfg->socks_secret);

    snprintf(cmds[n++], sizeof(cmds[0]), "interface %s", cfg->proxy_iface);
    snprintf(cmds[n++], sizeof(cmds[0]), "interface %s description Shadow-Fox",
             cfg->proxy_iface);
    snprintf(cmds[n++], sizeof(cmds[0]), "interface %s security-level public",
             cfg->proxy_iface);
    snprintf(cmds[n++], sizeof(cmds[0]), "interface %s ip global 1",
             cfg->proxy_iface);
    snprintf(cmds[n++], sizeof(cmds[0]), "interface %s proxy protocol socks5",
             cfg->proxy_iface);
    snprintf(cmds[n++], sizeof(cmds[0]), "interface %s proxy upstream %s %d",
             cfg->proxy_iface, lan, cfg->socks_port);
    snprintf(cmds[n++], sizeof(cmds[0]), "interface %s proxy socks5-udp",
             cfg->proxy_iface);
    if (secret[0]) {
        snprintf(cmds[n++], sizeof(cmds[0]), "interface %s authentication identity shadowfox",
                 cfg->proxy_iface);
        snprintf(cmds[n++], sizeof(cmds[0]), "interface %s authentication password %s",
                 cfg->proxy_iface, secret);
    }
    snprintf(cmds[n++], sizeof(cmds[0]), "interface %s up", cfg->proxy_iface);
    snprintf(cmds[n++], sizeof(cmds[0]), "system configuration save");

    for (int i = 0; i < n; i++) plan[i] = cmds[i];

    char what[160];
    snprintf(what, sizeof(what), "подключение %s создано", cfg->proxy_iface);
    ndmc_run_plan(bin, plan, n, what, req->peer, fd);
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

    /* Без полного списка подключений план — половина дела: политика
       создастся и разрешит своё подключение, а запреты остальных
       выпадут, и трафик пойдёт через провайдера при зелёном «настроена».
       Ровно так и было: сбой чтения молча давал gn = 0. */
    int trunc = 0;
    if (proc_run_capture(sargv, cfgtext, sizeof(cfgtext), 10, &trunc) != 0 || trunc) {
        log_warn("веб: конфигурация роутера не прочитана%s, политика не тронута",
                 trunc ? " целиком" : "");
        http_send_text(fd, 500, "text/plain; charset=utf-8",
                       "не удалось прочитать конфигурацию роутера, политика не тронута\n");
        return;
    }
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

    const char *plan[DNS_LINES_MAX + 4];
    for (int i = 0; i < n; i++) plan[i] = cmds[i];

    /* 160, а не 96: имя политики берётся из конфига и бывает в 63
       символа, а кириллица в UTF-8 вдвое длиннее в байтах. */
    char what[160];
    snprintf(what, sizeof(what), "политика %s настроена", cfg->policy);
    ndmc_run_plan(bin, plan, n, what, req->peer, fd);
}

/* ---- обновление пакета ---- */

/* Всё, что ходит за пакетами, делает shadowfox-update: он проверяет
   подпись индекса фида и SHA-256 пакета и только потом зовёт opkg.
   Демон сам opkg не запускает — иначе получилась бы вторая дорога в
   обход проверки. Скрипт ставится нашим же пакетом, но проверяем,
   что он на месте: без него честнее сказать «не найден», чем молчать. */
#define UPDATER "/opt/sbin/shadowfox-update"

static int updater_ok(void)
{
    return access(UPDATER, X_OK) == 0;
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

        /* Закрываем всё, что досталось по наследству: сокеты службы
           чужому процессу не нужны, а удержанный им порт потом не даёт
           подняться заново. CLOEXEC уже стоит, но здесь между fork и
           exec есть окно, да и sh может наплодить своих детей. */
        for (int fdn = 3; fdn < 256; fdn++) close(fdn);

        for (int fdn = 0; fdn < 3; fdn++) close(fdn);
        open("/dev/null", O_RDWR);
        if (dup(0) < 0 || dup(0) < 0) _exit(1);

        char sh[] = "/bin/sh", n0[] = "sh", c[] = "-c";
        char cmdbuf[1024];
        str_copy(cmdbuf, sizeof(cmdbuf), command);
        char *sargv[] = { n0, c, cmdbuf, NULL };
        execve(sh, sargv, child_env);
        _exit(127);
    }

    int st = 0;
    waitpid(first, &st, 0);            /* короткий: он сразу форкается и выходит */
    return 0;
}

#define UPDATE_LOG "/opt/var/log/shadowfox-update.log"

/* Проверка обновлений. opkg update ходит в сеть и занимает до минуты,
   а демон однопоточный: пока он ждал, стояли и перехват, и страница.
   Поэтому opkg запускается отвязанно и пишет результат в файл, а
   обработчик только читает файл. Свежий — отдаём, старый или нет —
   запускаем и отвечаем «идёт проверка», страница переспросит. */
#define UPDATE_FILE   "/opt/var/run/shadowfox.update"
#define UPDATE_FRESH  (6 * 3600)   /* сколько верим результату */
#define UPDATE_GUARD  60           /* не чаще запускаем повторно */

static time_t g_update_launched;

static void launch_update_check(void)
{
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "{ " UPDATER " check 2>&1; echo '## done'; } > %s.tmp && mv %s.tmp %s",
             UPDATE_FILE, UPDATE_FILE, UPDATE_FILE);
    spawn_detached(cmd);
    g_update_launched = time(NULL);
}

static void check_update(const http_req_t *req, int fd)
{
    char buf[2048];
    json_t j;

    json_init(&j, buf, sizeof(buf));
    json_obj_open(&j);
    json_kv_str(&j, "current", VERSION);

    if (!updater_ok()) {
        json_kv_bool(&j, "ok", 0);
        json_kv_bool(&j, "pending", 0);
        json_kv_str(&j, "why", "нет " UPDATER);
        json_kv_str(&j, "available", "");
        json_obj_close(&j);
        if (json_done(&j) == 0)
            http_send(fd, 200, "application/json; charset=utf-8", buf, strlen(buf));
        return;
    }

    char force[4] = "";
    http_query_get(req, "force", force, sizeof(force));

    time_t      now = time(NULL);
    struct stat st;
    int         have  = stat(UPDATE_FILE, &st) == 0;
    int         fresh = have && now - st.st_mtime < UPDATE_FRESH;

    /* Кнопка «Проверить» спрашивает заново, страница при открытии
       довольствуется свежим результатом. */
    int want_launch = (force[0] == '1') || !fresh;
    if (want_launch && now - g_update_launched >= UPDATE_GUARD) {
        launch_update_check();
        have = 0;   /* прежний ответ больше не показываем */
    }

    static char out[16 * 1024];
    int  ok = 0, failed = 0;
    char available[64] = "";
    char why[256]      = "проверка ещё идёт";

    /* Скрипт пишет строки вида available=…, xray=…, error=…. Версия в
       фиде та же, что стоит, — значит, обновления нет: пустое поле. */
    if (have && slurp(UPDATE_FILE, out, sizeof(out)) > 0 && strstr(out, "## done")) {
        ok = 1;
        why[0] = '\0';
        for (char *line = strtok(out, "\n"); line; line = strtok(NULL, "\n")) {
            char *t = str_trim(line);
            if (strncmp(t, "available=", 10) == 0) {
                if (strcmp(t + 10, VERSION) != 0)
                    str_copy(available, sizeof(available), t + 10);
            } else if (strncmp(t, "error=", 6) == 0) {
                ok = 0;
                failed = 1;
                str_copy(why, sizeof(why), t + 6);
            }
        }
    }

    json_kv_bool(&j, "ok", ok);
    json_kv_bool(&j, "pending", !ok && !failed && now - g_update_launched < 120);
    json_kv_str(&j, "why", why);
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
    if (!updater_ok()) {
        http_send_text(fd, 500, "text/plain; charset=utf-8", "нет " UPDATER "\n");
        return;
    }

    char command[512];
    snprintf(command, sizeof(command),
             "sleep 1; { date; " UPDATER " upgrade; date; } > %s 2>&1",
             UPDATE_LOG);

    if (spawn_detached(command) != 0) {
        http_send_text(fd, 500, "text/plain; charset=utf-8", "не запустить\n");
        return;
    }

    log_info("веб: запущено обновление пакета, запрос с %s", req->peer);
    http_send_text(fd, 200, "text/plain; charset=utf-8",
                   "обновление запущено\n");
}

#define XRAY_LOG "/opt/var/log/shadowfox-xray-install.log"

/* Установка ядра. Тянет мегабайты, поэтому запускается отвязанным
   процессом: иначе служба замерла бы на несколько минут и перестала
   ловить DNS. Страница ждёт появления ядра, спрашивая состояние. */
static void install_xray(const http_req_t *req, int fd)
{
    if (!updater_ok()) {
        http_send_text(fd, 500, "text/plain; charset=utf-8", "нет " UPDATER "\n");
        return;
    }

    char command[512];
    snprintf(command, sizeof(command),
             "sleep 1; { date; " UPDATER " install shadowfox-xray; date; } > %s 2>&1",
             XRAY_LOG);

    if (spawn_detached(command) != 0) {
        http_send_text(fd, 500, "text/plain; charset=utf-8", "не запустить\n");
        return;
    }

    log_info("веб: запущена установка ядра, запрос с %s", req->peer);
    http_send_text(fd, 200, "text/plain; charset=utf-8", "установка запущена\n");
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

    /* 0600 с момента создания и без хождения по ссылкам: раньше файл с
       ключом рождался 0644 и получал права только после rename. */
    unlink(tmp);
    int tfd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    FILE *f = tfd >= 0 ? fdopen(tfd, "w") : NULL;
    if (!f) {
        if (tfd >= 0) close(tfd);
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

/* Случайные байты из /dev/urandom. Возвращает 1, если получилось;
   предсказуемая метка сессии или nonce пустила бы посторонних, поэтому
   при неудаче лучше не выдать ничего. */
static int random_bytes(unsigned char *dst, size_t n)
{
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return 0;
    size_t got = fread(dst, 1, n, f);
    fclose(f);
    return got == n;
}

static void session_new(char *out, unsigned out_size)
{
    unsigned char raw[20];
    if (!random_bytes(raw, sizeof(raw))) {
        out[0] = '\0';
        return;
    }

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
    /* Текст ошибки может нести заголовок X-Detail из ответа роутера —
       чужие байты в нашей разметке. Пять символов экранируем. */
    char safe[512] = "";
    if (message) {
        size_t o = 0;
        for (const char *m = message; *m && o + 8 < sizeof(safe); m++) {
            const char *rep = *m == '<' ? "&lt;" : *m == '>' ? "&gt;"
                            : *m == '&' ? "&amp;" : *m == '"' ? "&quot;"
                            : *m == '\'' ? "&#39;" : NULL;
            if (rep) { size_t l = strlen(rep); memcpy(safe + o, rep, l); o += l; }
            else safe[o++] = *m;
        }
        safe[o] = '\0';
    }

    static char page[8192];
    snprintf(page, sizeof(page),
        "<!doctype html><meta charset=utf-8>"
        "<meta name=viewport content=\"width=device-width,initial-scale=1\">"
        "<title>Shadow Fox</title>"
        "<link rel=icon type=image/png href=/logo.png>"
        "<link rel=apple-touch-icon href=/logo.png>"
        "<style>"
        ":root{color-scheme:dark light}"
        "@font-face{font-family:Cinzel;font-weight:600;font-display:swap;"
        "src:url(/cinzel.woff2) format('woff2')}"
        /* Флекс с отступами, а не grid с центрированием: при открытой
           клавиатуре форма выше окна, и центрирование обрезает её
           сверху — доскроллить до логина уже нельзя. */
        "body{margin:0;min-height:100vh;min-height:100svh;display:flex;"
        "align-items:center;justify-content:center;padding:24px 16px;"
        "box-sizing:border-box;-webkit-text-size-adjust:100%%;"
        "background:#0a0d1e;color:#eef1ff;"
        "font:14px/1.55 system-ui,-apple-system,'Segoe UI',Roboto,sans-serif}"
        /* Та же аврора, что на странице: золото у лисы, фиолет в глубине. */
        "body::before{content:'';position:fixed;inset:0;z-index:-1;pointer-events:none;"
        "background:radial-gradient(700px 480px at 50%% 10%%,rgba(201,142,27,.2),transparent 62%%),"
        "radial-gradient(760px 620px at 100%% 100%%,rgba(99,80,255,.3),transparent 60%%),"
        "radial-gradient(1.2px 1.2px at 12%% 32%%,rgba(255,255,255,.55) 50%%,transparent 51%%),"
        "radial-gradient(1px 1px at 78%% 18%%,rgba(255,255,255,.45) 50%%,transparent 51%%),"
        "radial-gradient(1.4px 1.4px at 44%% 74%%,rgba(255,255,255,.5) 50%%,transparent 51%%),"
        "radial-gradient(1px 1px at 90%% 58%%,rgba(255,255,255,.4) 50%%,transparent 51%%),"
        "radial-gradient(1px 1px at 28%% 88%%,rgba(255,255,255,.35) 50%%,transparent 51%%)}"
        "form{background:rgba(18,23,52,.58);border:1px solid rgba(168,178,255,.13);"
        "border-radius:22px;padding:30px 30px 26px;width:min(400px,100%%);box-sizing:border-box;"
        "-webkit-backdrop-filter:blur(18px) saturate(150%%);backdrop-filter:blur(18px) saturate(150%%);"
        "box-shadow:inset 0 1px 0 rgba(255,255,255,.07),0 20px 50px rgba(0,0,0,.45)}"
        ".markw{position:relative;display:block;margin:0 auto 6px;width:min(168px,42%%);"
        "filter:drop-shadow(0 0 14px rgba(0,168,192,.5));animation:breathe 5s ease-in-out infinite}"
        "img{display:block;width:100%%;height:auto}"
        ".markw::after{content:'';position:absolute;inset:0;pointer-events:none;"
        "-webkit-mask:url(/logo.png) center/contain no-repeat;mask:url(/logo.png) center/contain no-repeat;"
        "background:linear-gradient(110deg,transparent 38%%,rgba(255,255,255,.08) 44%%,rgba(255,255,255,.6) 50%%,rgba(255,255,255,.1) 56%%,transparent 62%%);"
        "background-size:300%% 100%%;background-position:150%% 0;animation:glint 5s cubic-bezier(.4,0,.2,1) infinite}"
        "@keyframes glint{0%%{background-position:150%% 0}72%%,100%%{background-position:-150%% 0}}"
        "@keyframes breathe{0%%,100%%{filter:drop-shadow(0 0 10px rgba(0,168,192,.45))}"
        "50%%{filter:drop-shadow(0 0 24px rgba(0,168,192,.65))}}"
        "@media(prefers-reduced-motion:reduce){.markw{animation:none}.markw::after{display:none}}"
        "@media(max-width:600px){form{-webkit-backdrop-filter:none;backdrop-filter:none;"
        "background:rgba(18,23,52,.94)}}"
        "h1{margin:0 0 4px;text-align:center;color:#e0a83a;text-shadow:0 0 18px rgba(201,142,27,.45);"
        "font:600 26px/1.1 Cinzel,'Times New Roman',Georgia,serif;"
        "letter-spacing:.03em}"
        "p{margin:0 0 18px;color:#98a3cc;font-size:13px;text-align:center}"
        "label{display:block;color:#98a3cc;font-size:12.5px;margin:12px 0 5px}"
        /* 16px не для красоты: Safari на iPhone увеличивает страницу при
           фокусе на поле мельче шестнадцати, и форма уезжает за край.
           Размер шрифта задан отдельно от семейства — сокращение
           «font: 14px/1.4 inherit» неверно, inherit там не семейство. */
        "input{width:100%%;box-sizing:border-box;background:rgba(7,10,26,.6);color:#eef1ff;"
        "border:1px solid rgba(168,178,255,.16);border-radius:10px;padding:11px 12px;"
        "font-family:inherit;font-size:16px;line-height:1.4}"
        "input:focus{outline:0;border-color:#e0a83a;box-shadow:0 0 0 3px rgba(201,142,27,.2)}"
        "button{width:100%%;margin-top:20px;background:linear-gradient(180deg,#e6b44a,#b8821c);"
        "color:#2a1a00;border:0;border-radius:11px;padding:12px;font-family:inherit;font-size:15px;"
        "font-weight:650;line-height:1;cursor:pointer;"
        "box-shadow:inset 0 1px 0 rgba(255,255,255,.35),0 8px 24px rgba(201,142,27,.4)}"
        "button:hover{filter:brightness(1.06)}"
        ".bad{color:#ff8a5c;font-size:13px;margin-top:14px}"
        "</style>"
        "<form method=post action=/login>"
        "<span class=markw><img src=/logo.png alt=\"\" width=168 height=168></span>"
        "<h1>Shadow Fox</h1>"
        "<p>Логин и пароль администратора роутера</p>"
        "<label>Логин</label><input name=login autofocus autocomplete=username>"
        "<label>Пароль</label>"
        "<input name=password type=password autocomplete=current-password>"
        "<button>Войти</button>"
        "<div class=bad id=msg hidden></div>"
        "<noscript><div class=bad>Для входа нужен JavaScript: ответ роутеру "
        "считается в браузере, чтобы пароль не уходил по сети</div></noscript>"
        "%s%s%s</form>"
        /* Язык — тот же ключ, что у страницы: localStorage общий. */
        "<script>(function(){var l;try{l=localStorage.getItem('sf-lang')}catch(e){}"
        "if(!l)l=(navigator.language||'ru').toLowerCase().indexOf('ru')===0?'ru':'en';"
        "if(l==='ru')return;document.documentElement.lang='en';"
        "var m={'Логин и пароль администратора роутера':'Router administrator login and password',"
        "'Логин':'Login','Пароль':'Password','Войти':'Sign in',"
        "'Для входа нужен JavaScript: ответ роутеру считается в браузере, чтобы пароль не уходил по сети':"
        "'JavaScript is required: the answer to the router is computed in the browser so the password never leaves it'};"
        "document.querySelectorAll('p,label,button,noscript div').forEach(function(e){var t=e.textContent.trim();if(m[t])e.textContent=m[t]});})()</script>"
        "<script src=/login.js></script>",
        message && *message ? "<div class=bad>" : "",
        message && *message ? safe : "",
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
#define LOGIN_PEERS     16

/* Счётчик на адрес клиента, а не один на всех: раньше три неверных
   пароля с любого устройства сети закрывали вход всем на минуту, и
   повторять это можно было без конца. Пауза растёт с каждой серией —
   до получаса, — а перебирающий получает не три попытки в минуту, а
   всё меньше. Общий порог остаётся второй линией, выше. */
typedef struct {
    char  peer[64];
    int   tries;
    int   streak;    /* сколько серий подряд */
    long  until;
    long  last;
} login_peer_t;

static login_peer_t g_peers[LOGIN_PEERS];
static int          g_bad_total;      /* общий счётчик за окно */
static long         g_bad_window;

static login_peer_t *peer_slot(const char *peer, long now)
{
    login_peer_t *oldest = &g_peers[0];
    for (int i = 0; i < LOGIN_PEERS; i++) {
        if (g_peers[i].peer[0] && !strcmp(g_peers[i].peer, peer)) return &g_peers[i];
        if (g_peers[i].last < oldest->last) oldest = &g_peers[i];
    }
    memset(oldest, 0, sizeof(*oldest));
    str_copy(oldest->peer, sizeof(oldest->peer), peer);
    oldest->last = now;
    return oldest;
}

/* Начатые входы: страница получила realm и challenge, но ответ ещё не
   прислала. Слот живёт две минуты. Nonce — чтобы страница вернула
   именно свой challenge, а не чужой из соседнего слота. */
static int random_bytes(unsigned char *dst, size_t n);

#define AUTH_PENDING_MAX 8
#define AUTH_PENDING_TTL 120

typedef struct {
    char          nonce[33];
    ndm_pending_t p;
    long          at;
} auth_pending_t;

static auth_pending_t g_auth[AUTH_PENDING_MAX];

static int router_host(const config_t *cfg, char *host, size_t size)
{
    if (cfg->router_host[0]) { str_copy(host, size, cfg->router_host); return 1; }
    return iface_ipv4(cfg->capture_iface, host, size);
}

/* Первый шаг входа. Пароль страница не шлёт: она берёт отсюда realm и
   challenge, считает ответ сама и присылает его в /login. */
static void auth_begin(const http_req_t *req, int fd, const config_t *cfg)
{
    long now = (long)time(NULL);

    char buf[1024];
    json_t j;
    json_init(&j, buf, sizeof(buf));
    json_obj_open(&j);

    login_peer_t *lp = peer_slot(req->peer, now);
    if (lp->until > now) {
        json_kv_bool(&j, "ok", 0);
        json_kv_str(&j, "why", "слишком много неудачных попыток, подожди минуту");
        goto out;
    }

    char host[64] = "";
    if (!router_host(cfg, host, sizeof(host))) {
        json_kv_bool(&j, "ok", 0);
        json_kv_str(&j, "why", "не узнать адрес роутера, задай routerHost");
        goto out;
    }

    ndm_pending_t p;
    char          err[160] = "";
    if (ndm_begin(host, cfg->router_port, &p, err, sizeof(err)) != NDM_OK) {
        json_kv_bool(&j, "ok", 0);
        json_kv_str(&j, "why", err[0] ? err : "роутер не ответил");
        goto out;
    }

    /* Свободный либо самый старый слот. */
    auth_pending_t *slot = &g_auth[0];
    for (int i = 0; i < AUTH_PENDING_MAX; i++) {
        if (!g_auth[i].nonce[0] || now - g_auth[i].at > AUTH_PENDING_TTL) { slot = &g_auth[i]; break; }
        if (g_auth[i].at < slot->at) slot = &g_auth[i];
    }

    unsigned char rnd[16];
    if (!random_bytes(rnd, sizeof(rnd))) {
        json_kv_bool(&j, "ok", 0);
        json_kv_str(&j, "why", "нет случайных чисел");
        goto out;
    }
    hex_encode(rnd, sizeof(rnd), slot->nonce);
    slot->p  = p;
    slot->at = now;

    json_kv_bool(&j, "ok", 1);
    json_kv_str(&j, "realm", p.realm);
    json_kv_str(&j, "challenge", p.challenge);
    json_kv_str(&j, "nonce", slot->nonce);

out:
    json_obj_close(&j);
    if (json_done(&j) != 0) {
        http_send_text(fd, 500, "text/plain; charset=utf-8", "не поместилось\n");
        return;
    }
    http_send(fd, 200, "application/json; charset=utf-8", buf, strlen(buf));
}

static void do_login(const http_req_t *req, int fd, const config_t *cfg)
{
    long now = (long)time(NULL);

    login_peer_t *lp = peer_slot(req->peer, now);
    lp->last = now;

    /* Общая линия: двадцать неудач за минуту со всех адресов разом —
       это уже не опечатки. */
    if (now - g_bad_window > 60) { g_bad_window = now; g_bad_total = 0; }

    if (lp->until > now || g_bad_total >= 20) {
        long wait = lp->until > now ? lp->until - now : 60;
        /* 256, а не 128: текст кириллический, в UTF-8 он занимает вдвое
           больше байт, чем символов, и в 128 не помещался — строка
           резалась посреди многобайтового символа. */
        char msg[256];
        snprintf(msg, sizeof(msg),
                 "Слишком много неудачных попыток. Подожди %ld секунд — "
                 "иначе роутер заблокирует адрес сам", wait);
        send_login(fd, msg);
        return;
    }

    char login[128] = "", answer[80] = "", nonce[40] = "";
    form_field(req->body, req->body_len, "login",  login,  sizeof(login));
    form_field(req->body, req->body_len, "answer", answer, sizeof(answer));
    form_field(req->body, req->body_len, "nonce",  nonce,  sizeof(nonce));

    if (!login[0]) { send_login(fd, "Введи логин"); return; }

    /* Пароля здесь больше нет: приходит ответ, посчитанный на странице.
       Если пришёл сам пароль — старая форма из кеша — просим обновить. */
    if (!answer[0] || !nonce[0]) {
        send_login(fd, "Страница устарела — обнови её и войди снова");
        return;
    }

    auth_pending_t *slot = NULL;
    for (int i = 0; i < AUTH_PENDING_MAX; i++)
        if (g_auth[i].nonce[0] && !strcmp(g_auth[i].nonce, nonce)) slot = &g_auth[i];
    if (!slot || now - slot->at > AUTH_PENDING_TTL) {
        send_login(fd, "Запрос входа устарел — попробуй ещё раз");
        return;
    }
    ndm_pending_t p = slot->p;
    memset(slot, 0, sizeof(*slot));   /* одноразовый */

    /* Спрашивать роутер надо с адреса сети, а не с петли: на 127.0.0.1
       он отвечает «insufficient security level» и заголовков схемы не
       присылает вовсе. */
    char host[64] = "";
    if (!router_host(cfg, host, sizeof(host))) {
        send_login(fd, "не узнать адрес роутера, задай routerHost");
        return;
    }

    char         err[160] = "";
    ndm_result_t r = ndm_finish(host, cfg->router_port, &p, login, answer,
                                err, sizeof(err));

    if (r != NDM_OK) {
        if (r == NDM_DENIED) g_bad_total++;
        if (r == NDM_DENIED && ++lp->tries >= LOGIN_TRIES) {
            lp->tries = 0;
            lp->streak++;
            long cool = LOGIN_COOLDOWN;
            for (int i = 1; i < lp->streak && cool < 1800; i++) cool *= 2;
            lp->until = now + cool;
        }
        log_warn("веб: вход отклонён (%s), запрос с %s",
                 err[0] ? err : "не подошло", req->peer);
        send_login(fd, err[0] ? err : "Неверный логин или пароль");
        return;
    }

    lp->tries  = 0;
    lp->streak = 0;
    lp->until  = 0;

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

/* Запрос с чужой страницы. SameSite у cookie не различает порт: панель
   роутера на :80 и любой пакет Entware со своей страницей — для
   браузера тот же сайт. Поэтому на POST сверяем Origin с Host: браузер
   на межсайтовый POST ставит Origin всегда, а совпасть чужой не может.
   Без Origin (curl, старые клиенты) пропускаем — это не браузер. */
static int foreign_origin(const http_req_t *req)
{
    if (strcmp(req->method, "POST") != 0) return 0;
    if (!req->origin[0] || !req->host[0]) return 0;

    const char *o = req->origin;
    if (!strncmp(o, "http://", 7)) o += 7;
    else if (!strncmp(o, "https://", 8)) o += 8;

    return strcmp(o, req->host) != 0;
}

static void handle(const http_req_t *req, int fd, void *ctx)
{
    webctx_t *c = ctx;

    if (!strcmp(req->path, "/cinzel.woff2")) {
        http_send_gzip(fd, "font/woff2", web_font, web_font_len);
        return;
    }

    /* Без проверки входа: скрипт нужен самой форме входа. */
    if (!strcmp(req->path, "/login.js")) {
        http_send_gzip(fd, "application/javascript; charset=utf-8",
                       web_loginjs, web_loginjs_len);
        return;
    }

    if (!strcmp(req->path, "/logo.png") || !strcmp(req->path, "/favicon.ico")) {
        /* Без проверки входа: картинка нужна самой форме входа, а тайны
           в ней нет. favicon.ico браузеры спрашивают сами, ещё до
           разметки — отдаём тот же PNG, они его принимают. */
        http_send_gzip(fd, "image/png", web_logo, web_logo_len);
        return;
    }

    if (foreign_origin(req)) {
        log_warn("веб: POST %s с чужого источника %s, отказ", req->path, req->origin);
        http_send_text(fd, 403, "text/plain; charset=utf-8",
                       "запрос с чужой страницы\n");
        return;
    }

    if (!strcmp(req->path, "/auth") && !strcmp(req->method, "GET")) {
        auth_begin(req, fd, c->cfg);
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

    if (!strcmp(req->path, "/xray") && !strcmp(req->method, "POST")) {
        install_xray(req, fd);
        return;
    }

    if (!strcmp(req->path, "/update")) {
        if (!strcmp(req->method, "POST")) do_update(req, fd);
        else                              check_update(req, fd);
        return;
    }

    if (!strcmp(req->path, "/policy") && !strcmp(req->method, "POST")) {
        apply_policy(req, fd, c->cfg);
        return;
    }

    if (!strcmp(req->path, "/proxy") && !strcmp(req->method, "POST")) {
        apply_proxy(req, fd, c->cfg);
        return;
    }

    if (!strcmp(req->path, "/web") && !strcmp(req->method, "POST")) {
        apply_web(req, fd, c->cfg);
        return;
    }

    if (!strcmp(req->path, "/dns")) {
        if (!strcmp(req->method, "POST")) apply_dns(req, fd);
        else                              send_dns(fd, c->cfg);
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
