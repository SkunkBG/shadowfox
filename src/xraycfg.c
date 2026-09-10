#include "xraycfg.h"
#include "jsonw.h"

#include <stdio.h>
#include <string.h>

#define TAG_PROXY    "proxy"
#define TAG_DIRECT   "direct"
#define TAG_BLOCK    "block"
#define TAG_FRAGMENT "fragment"
#define TAG_SOCKS_IN "socks-in"
#define TAG_BALANCER "balancer"

/* Общий префикс тегов исходящих. По нему балансировщик и наблюдатель
   отбирают узлы, поэтому он обязан совпадать в трёх местах. */
#define PROXY_PREFIX "proxy-"

void xraycfg_defaults(xraycfg_opts_t *o)
{
    memset(o, 0, sizeof(*o));
    o->listen     = "127.0.0.1";
    o->socks_port = 2080;
    /* Фрагментация ClientHello включена — но применяется только к
       обычному TLS, см. wants_fragment. Шума нет: в ядре он живёт лишь
       в UDP-ветке freedom, а VLESS ходит по TCP, так что «шум в UDP»
       не применялся никогда, зато тянул за собой dialerProxy и лишал
       Vision splice. Убран по итогам аудита. */
    o->fragment   = 1;
    o->fingerprint = "";
    /* Сниффинг выключен: для маршрутизации внутри ядра он не нужен —
       всё уходит в туннель, — а HydraRoute на той же линии живёт без
       него. Меньше отличий от проверенной конфигурации. */
    o->sniffing   = 0;
    o->log_level  = "warning";
    o->probe_url  = "https://www.gstatic.com/generate_204";
    o->probe_interval = "5m";
}

/* Какой отпечаток uTLS объявлять.

   Порядок: перекрытие из конфига, затем пришедший в ссылке, затем
   запасной — chrome, умолчание самого ядра. Раньше запасным и
   принудительным был firefox из соображения «chrome распознают первым».
   Аудит по исходникам показал, что это перевёрнуто: сервер Reality
   отпечаток не проверяет вовсе, а DPI ищет не самый частый отпечаток, а
   несоответствие отпечатка реальному браузеру. Самый частый — лучшее
   прикрытие; одинаковый Firefox у всех наших пользователей из сетей, где
   настоящего Firefox почти нет, — это кластер, то есть сигнал.
   Перекрытие остаётся ручкой для разбора полётов. */
static const char *pick_fingerprint(const node_t *n, const xraycfg_opts_t *o)
{
    if (o->fingerprint && o->fingerprint[0]) return o->fingerprint;
    if (n->fingerprint[0])                   return n->fingerprint;
    return "chrome";
}

/* Резать ли ClientHello этому узлу. У Reality имя сервера — разрешённый
   домен, прятать его от DPI нечего, а поток кусков по несколько сотен
   байт с паузами — сам по себе паттерн, которого у браузера нет. Плюс
   dialerProxy превращает соединение в pipe, и splice у Vision невозможен
   — каждый байт дважды идёт через горутины, на процессоре роутера это
   заметно. Обычный TLS — другое дело: там SNI открытый, и резать его
   есть смысл. */
static int wants_fragment(const node_t *n, const xraycfg_opts_t *o)
{
    return o->fragment && strcmp(n->security, "tls") == 0;
}

static void build_log(json_t *j, const xraycfg_opts_t *o)
{
    json_key(j, "log");
    json_obj_open(j);
    json_kv_str(j, "loglevel", o->log_level ? o->log_level : "warning");
    /* Без этого ядро форматирует строку с адресом назначения на каждое
       соединение — впустую, вывод всё равно уходит в /dev/null. */
    json_kv_str(j, "access", "none");
    if (o->error_log && o->error_log[0]) {
        json_kv_str(j, "error", o->error_log);
        /* В ошибках ядро печатает адреса клиентов и назначения. Нам для
           диагноза хватает половины: видно сеть, не видно устройство. */
        json_kv_str(j, "maskAddress", "half");
    }
    json_obj_close(j);
}

static void build_inbound(json_t *j, const xraycfg_opts_t *o)
{
    json_obj_open(j);
    json_kv_str(j, "tag", TAG_SOCKS_IN);

    /* Адрес входа задаётся явно. У Xray listen по умолчанию 0.0.0.0, и
       neofit его не задавал — на роутере поднимался открытый SOCKS5 без
       авторизации на всех интерфейсах.
       По умолчанию петля, но штатный прокси-клиент Keenetic может ходить
       на LAN-адрес роутера, а не на localhost. Тогда сюда подставляется
       этот адрес: он всё равно уже не 0.0.0.0. */
    json_kv_str(j, "listen", o->listen && o->listen[0] ? o->listen : "127.0.0.1");
    json_kv_int(j, "port", o->socks_port);
    json_kv_str(j, "protocol", "socks");

    json_key(j, "settings");
    json_obj_open(j);
    if (o->socks_pass && o->socks_pass[0]) {
        json_kv_str(j, "auth", "password");
        json_key(j, "accounts");
        json_arr_open(j);
        json_obj_open(j);
        json_kv_str(j, "user", o->socks_user && o->socks_user[0] ? o->socks_user : "shadowfox");
        json_kv_str(j, "pass", o->socks_pass);
        json_obj_close(j);
        json_arr_close(j);
    } else {
        json_kv_str(j, "auth", "noauth");
    }
    json_kv_bool(j, "udp", 1);
    json_obj_close(j);

    if (o->sniffing) {
        json_key(j, "sniffing");
        json_obj_open(j);
        json_kv_bool(j, "enabled", 1);
        json_key(j, "destOverride");
        json_arr_open(j);
        json_str(j, "http");
        json_str(j, "tls");
        json_str(j, "quic");
        json_arr_close(j);
        json_obj_close(j);
    }

    json_obj_close(j);
}

static void build_stream(json_t *j, const node_t *n, const xraycfg_opts_t *o)
{
    json_key(j, "streamSettings");
    json_obj_open(j);
    json_kv_str(j, "network", n->network);
    json_kv_str(j, "security", n->security);

    if (strcmp(n->security, "reality") == 0) {
        json_key(j, "realitySettings");
        json_obj_open(j);
        json_kv_str(j, "serverName", n->sni);
        json_kv_str(j, "publicKey", n->public_key);
        json_kv_str(j, "shortId", n->short_id);
        json_kv_str(j, "spiderX", n->spider_x[0] ? n->spider_x : "/");
        /* Отпечаток берём из ссылки. Подставлять свой нельзя: сервер
           ожидает конкретный, и расхождение видно снаружи. */
        json_kv_str(j, "fingerprint", pick_fingerprint(n, o));
        json_obj_close(j);
    } else if (strcmp(n->security, "tls") == 0) {
        json_key(j, "tlsSettings");
        json_obj_open(j);
        if (n->sni[0]) json_kv_str(j, "serverName", n->sni);
        json_kv_str(j, "fingerprint", pick_fingerprint(n, o));
        /* alpn пишем только если он пришёл в ссылке. neofit прописывал
           ["h2","http/1.1"] всегда, рассогласуя ALPN с отпечатком uTLS. */
        if (n->alpn[0]) json_kv_str_list(j, "alpn", n->alpn, ',');
        /* allowInsecure из ссылки не переносим, даже если он там есть.
           У VLESS с encryption none TLS — единственный слой защиты, и
           один параметр в подписке, скопированной из чата, снимал бы
           проверку сертификата: любой на пути читал бы трафик. Демон
           предупреждает в журнале, что ссылка это просила. */
        json_obj_close(j);
    }

    if (strcmp(n->network, "ws") == 0 ||
        strcmp(n->network, "httpupgrade") == 0) {
        json_key(j, strcmp(n->network, "ws") == 0
                    ? "wsSettings" : "httpupgradeSettings");
        json_obj_open(j);
        json_kv_str(j, "path", n->path[0] ? n->path : "/");
        if (n->host[0]) json_kv_str(j, "host", n->host);
        json_obj_close(j);
    } else if (strcmp(n->network, "grpc") == 0) {
        json_key(j, "grpcSettings");
        json_obj_open(j);
        json_kv_str(j, "serviceName", n->service_name);
        if (n->authority[0]) json_kv_str(j, "authority", n->authority);
        if (!strcmp(n->mode, "multi")) json_kv_bool(j, "multiMode", 1);
        json_obj_close(j);
    } else if (strcmp(n->network, "xhttp") == 0 ||
               strcmp(n->network, "splithttp") == 0) {
        json_key(j, "xhttpSettings");
        json_obj_open(j);
        json_kv_str(j, "path", n->path[0] ? n->path : "/");
        if (n->host[0]) json_kv_str(j, "host", n->host);
        if (n->mode[0]) json_kv_str(j, "mode", n->mode);
        json_obj_close(j);
    } else if (strcmp(n->network, "tcp") == 0 &&
               strcmp(n->header_type, "http") == 0) {
        json_key(j, "tcpSettings");
        json_obj_open(j);
        json_key(j, "header");
        json_obj_open(j);
        json_kv_str(j, "type", "http");
        /* Без Host и пути заголовок бесполезен: сервер с маскировкой
           под HTTP ждёт своего имени. Раньше писался один type. */
        if (n->host[0] || n->path[0]) {
            json_key(j, "request");
            json_obj_open(j);
            if (n->path[0]) json_kv_str_list(j, "path", n->path, ',');
            if (n->host[0]) {
                json_key(j, "headers");
                json_obj_open(j);
                json_kv_str_list(j, "Host", n->host, ',');
                json_obj_close(j);
            }
            json_obj_close(j);
        }
        json_obj_close(j);
        json_obj_close(j);
    }

    /* Фрагментация делается отдельным исходящим, а трафик узла
       направляется через него. Своего поля fragment у vless нет. */
    if (wants_fragment(n, o)) {
        json_key(j, "sockopt");
        json_obj_open(j);
        json_kv_str(j, "dialerProxy", TAG_FRAGMENT);
        json_obj_close(j);
    }

    json_obj_close(j);
}

static void build_proxy_outbound(json_t *j, const node_t *n,
                                 const xraycfg_opts_t *o, const char *tag)
{
    json_obj_open(j);
    json_kv_str(j, "tag", tag);
    json_kv_str(j, "protocol", n->protocol);

    json_key(j, "settings");
    json_obj_open(j);
    json_key(j, "vnext");
    json_arr_open(j);
    json_obj_open(j);
    json_kv_str(j, "address", n->address);
    json_kv_int(j, "port", n->port);
    json_key(j, "users");
    json_arr_open(j);
    json_obj_open(j);
    json_kv_str(j, "id", n->id);
    json_kv_str(j, "encryption", n->encryption);
    if (n->flow[0]) json_kv_str(j, "flow", n->flow);
    json_obj_close(j);
    json_arr_close(j);
    json_obj_close(j);
    json_arr_close(j);
    json_obj_close(j);

    build_stream(j, n, o);
    json_obj_close(j);
}

static void build_fragment_outbound(json_t *j, const xraycfg_opts_t *o)
{
    (void)o;
    json_obj_open(j);
    json_kv_str(j, "tag", TAG_FRAGMENT);
    json_kv_str(j, "protocol", "freedom");

    json_key(j, "settings");
    json_obj_open(j);

    /* Куски по 300-500 байт, а не 100-200: ClientHello с ML-KEM около
       1,7 КБ, и мелкая нарезка давала до восемнадцати записей с паузой
       после каждой — сотни миллисекунд на каждое рукопожатие. */
    json_key(j, "fragment");
    json_obj_open(j);
    json_kv_str(j, "packets", "tlshello");
    json_kv_str(j, "length", "300-500");
    json_kv_str(j, "interval", "10-20");
    json_obj_close(j);

    json_obj_close(j);
    json_obj_close(j);
}

int xraycfg_build_list(const nodelist_t *l, const xraycfg_opts_t *o,
                       char *buf, size_t size)
{
    if (!l || !o || !buf || l->count <= 0) return -1;

    const int balanced = l->count > 1;

    json_t j;
    json_init(&j, buf, size);

    json_obj_open(&j);
    build_log(&j, o);

    if (balanced) {
        /* Наблюдатель периодически измеряет узлы, а балансировщик
           выбирает самый быстрый живой. Без него strategy leastPing
           не с чем работать. */
        json_key(&j, "observatory");
        json_obj_open(&j);
        json_key(&j, "subjectSelector");
        json_arr_open(&j);
        json_str(&j, PROXY_PREFIX);
        json_arr_close(&j);
        json_kv_str(&j, "probeUrl", o->probe_url);
        json_kv_str(&j, "probeInterval", o->probe_interval);
        json_obj_close(&j);
    }

    json_key(&j, "inbounds");
    json_arr_open(&j);
    build_inbound(&j, o);
    json_arr_close(&j);

    json_key(&j, "outbounds");
    json_arr_open(&j);
    for (int i = 0; i < l->count; i++) {
        char tag[32];
        snprintf(tag, sizeof(tag), PROXY_PREFIX "%d", i);
        build_proxy_outbound(&j, &l->items[i], o, tag);
    }
    int need_fragment = 0;
    for (int i = 0; i < l->count; i++)
        if (wants_fragment(&l->items[i], o)) need_fragment = 1;
    if (need_fragment) build_fragment_outbound(&j, o);

    json_obj_open(&j);
    json_kv_str(&j, "tag", TAG_DIRECT);
    json_kv_str(&j, "protocol", "freedom");
    json_obj_close(&j);

    json_obj_open(&j);
    json_kv_str(&j, "tag", TAG_BLOCK);
    json_kv_str(&j, "protocol", "blackhole");
    json_obj_close(&j);
    json_arr_close(&j);

    json_key(&j, "routing");
    json_obj_open(&j);
    json_kv_str(&j, "domainStrategy", "AsIs");

    if (balanced) {
        json_key(&j, "balancers");
        json_arr_open(&j);
        json_obj_open(&j);
        json_kv_str(&j, "tag", TAG_BALANCER);
        json_key(&j, "selector");
        json_arr_open(&j);
        json_str(&j, PROXY_PREFIX);
        json_arr_close(&j);
        json_key(&j, "strategy");
        json_obj_open(&j);
        json_kv_str(&j, "type", "leastPing");
        json_obj_close(&j);
        json_obj_close(&j);
        json_arr_close(&j);
    }

    json_key(&j, "rules");
    json_arr_open(&j);
    json_obj_open(&j);
    json_kv_str(&j, "type", "field");
    json_key(&j, "inboundTag");
    json_arr_open(&j);
    json_str(&j, TAG_SOCKS_IN);
    json_arr_close(&j);
    if (balanced) {
        json_kv_str(&j, "balancerTag", TAG_BALANCER);
    } else {
        json_kv_str(&j, "outboundTag", PROXY_PREFIX "0");
    }
    json_obj_close(&j);
    json_arr_close(&j);
    json_obj_close(&j);

    json_obj_close(&j);

    return json_done(&j);
}

int xraycfg_build(const node_t *n, const xraycfg_opts_t *o,
                  char *buf, size_t size)
{
    if (!n) return -1;

    nodelist_t l;
    nodelist_init(&l);
    l.items[0] = *n;
    l.count    = 1;

    return xraycfg_build_list(&l, o, buf, size);
}

/* ---- конфиг из подписки Xray JSON ---- */

static int span_is(const xjson_span_t *k, const char *name)
{
    return k->len == strlen(name) && !memcmp(k->ptr, name, k->len);
}

static int span_has(const xjson_span_t *v, const char *needle)
{
    return memmem(v->ptr, v->len, needle, strlen(needle)) != NULL;
}

/* routing панели: правила с geoip:/geosite:/ext: выбрасываются. */
static int copy_routing(json_t *j, const xjson_span_t *routing)
{
    json_key(j, "routing");
    json_obj_open(j);
    const char *p = routing->ptr + 1, *end = routing->ptr + routing->len;
    xjson_span_t k, v;
    int rc;
    while ((rc = xjson_next_member(&p, end, &k, &v)) == 1) {
        char key[64];
        if (k.len >= sizeof(key)) return -1;
        memcpy(key, k.ptr, k.len); key[k.len] = '\0';
        if (!span_is(&k, "rules") || v.len < 2 || *v.ptr != '[') {
            json_key(j, key);
            json_rawn(j, v.ptr, v.len);
            continue;
        }
        json_key(j, "rules");
        json_arr_open(j);
        const char *q = xjson_ws(v.ptr + 1, v.ptr + v.len), *qe = v.ptr + v.len;
        while (q < qe && *q != ']') {
            if (*q == ',') { q = xjson_ws(q + 1, qe); continue; }
            const char *e = xjson_skip_value(q, qe);
            if (!e) return -1;
            xjson_span_t rule = { q, (size_t)(e - q) };
            if (!span_has(&rule, "geoip:") && !span_has(&rule, "geosite:") &&
                !span_has(&rule, "ext:"))
                json_rawn(j, rule.ptr, rule.len);
            q = xjson_ws(e, qe);
        }
        json_arr_close(j);
    }
    if (rc < 0) return -1;
    json_obj_close(j);
    return 0;
}

int xraycfg_build_from_json(const xjson_item_t *it, const xraycfg_opts_t *o,
                            char *buf, size_t size)
{
    if (!it || !o || !buf || !it->whole.ptr || it->whole.len < 2) return -1;

    json_t j;
    json_init(&j, buf, size);
    json_obj_open(&j);
    build_log(&j, o);

    json_key(&j, "inbounds");
    json_arr_open(&j);
    build_inbound(&j, o);
    json_arr_close(&j);

    const char *p = it->whole.ptr + 1, *end = it->whole.ptr + it->whole.len;
    xjson_span_t k, v;
    int rc;
    while ((rc = xjson_next_member(&p, end, &k, &v)) == 1) {
        if (span_is(&k, "log") || span_is(&k, "inbounds") || span_is(&k, "dns") ||
            span_is(&k, "remarks"))
            continue;
        if (span_is(&k, "routing") && v.len >= 2 && *v.ptr == '{') {
            if (copy_routing(&j, &v) != 0) return -1;
            continue;
        }
        char key[64];
        if (k.len >= sizeof(key)) return -1;
        memcpy(key, k.ptr, k.len); key[k.len] = '\0';
        json_key(&j, key);
        json_rawn(&j, v.ptr, v.len);
    }
    if (rc < 0) return -1;

    json_obj_close(&j);
    return json_done(&j) == 0 ? 0 : -1;
}
