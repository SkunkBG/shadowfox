#include "webui.h"

#include <arpa/inet.h>
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

    return strcmp(h->bind_addr, addr) != 0 ||
           h->port != cfg->web_port ||
           strcmp(h->token, cfg->web_token) != 0;
}

int webui_open(http_t *h, const config_t *cfg, char *err, unsigned err_size)
{
    if (!h || !cfg) return -1;

    char addr[64];
    if (webui_addr(cfg, addr, sizeof(addr), err, err_size) != 0) return -1;

    http_init(h);
    str_copy(h->token, sizeof(h->token), cfg->web_token);

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

static void handle(const http_req_t *req, int fd, void *ctx)
{
    webctx_t *c = ctx;

    if (!strcmp(req->path, "/") || !strcmp(req->path, "/index.html")) {
        http_send_gzip(fd, "text/html; charset=utf-8", web_page, web_page_len);
        return;
    }

    if (!strcmp(req->path, "/data")) {
        send_data(req, fd, c->engine, c->cfg);
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
