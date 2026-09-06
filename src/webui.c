#include "webui.h"
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

int webui_open(http_t *h, const config_t *cfg, char *err, unsigned err_size)
{
    if (!h || !cfg) return -1;

    char addr[64];
    if (cfg->web_bind[0]) {
        str_copy(addr, sizeof(addr), cfg->web_bind);
    } else if (!iface_ipv4(cfg->capture_iface, addr, sizeof(addr))) {
        if (err)
            snprintf(err, err_size,
                     "не узнать адрес на %s, задай webBind", cfg->capture_iface);
        return -1;
    }

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

static void send_data(int fd, struct engine *ce, const config_t *cfg)
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

    /* Содержимое файлов отдаём как есть: страница их же и правит. */
    static char text[64 * 1024];
    const char *parts[] = { "domains", "cidrs", "nodes", NULL };
    for (int i = 0; parts[i]; i++) {
        char path[CFG_PATH_MAX + 32];
        file_for(cfg, parts[i], path, sizeof(path));
        if (slurp(path, text, sizeof(text)) < 0) text[0] = '\0';
        json_kv_str(&j, parts[i], text);
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
        send_data(fd, c->engine, c->cfg);
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
