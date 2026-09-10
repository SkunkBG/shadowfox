#include "xraycfg.h"
#include "util.h"
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

/* Панель — чужой код, а ядро на роутере работает с правами root.
   Поэтому из её конфига берётся только то, без чего сборка серверов
   не соберётся, и только в тех формах, которые не дают панели власти
   над роутером:
     outbounds — протоколы туннеля, freedom и blackhole; без sockopt
                 (mark/interface/tproxy ломают маршрутизацию по меткам),
                 без reverse (вход оператора в домашнюю сеть), без
                 redirect и dialerProxy;
     routing   — правила без geo (файлов нет) и без webhook (адреса
                 устройств уходили бы на URL панели), плюс своё
                 замыкающее правило: всё с нашего входа — в балансировщик
                 панели либо в первый серверный outbound. Без него трафик
                 без совпавшего правила шёл бы в первый outbound панели,
                 каким бы он ни был;
     observatory / burstObservatory — как есть, без connectivity (по
                 нему ядро ходит наружу мимо туннеля).
   Всё остальное (api, metrics, env, stats, policy, transport, fakedns…)
   отбрасывается. Имена ключей ядро сравнивает без учёта регистра и при
   дубликате берёт последний, поэтому ключи сравниваются в нижнем
   регистре, дубликаты и комментарии — отказ. */

static int span_is(const xjson_span_t *k, const char *name)
{
    if (k->len != strlen(name)) return 0;
    for (size_t i = 0; i < k->len; i++) {
        char c = k->ptr[i];
        if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
        if (c != name[i]) return 0;
    }
    return 1;
}

/* Подстрока без учёта регистра внутри куска. */
static int span_has(const xjson_span_t *v, const char *needle)
{
    size_t n = strlen(needle);
    if (!n || v->len < n) return 0;
    for (size_t i = 0; i + n <= v->len; i++) {
        size_t j = 0;
        for (; j < n; j++) {
            char c = v->ptr[i + j];
            if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
            if (c != needle[j]) break;
        }
        if (j == n) return 1;
    }
    return 0;
}

/* Комментарии (две косые или косая со звёздочкой) вне строк: ядро их
   вырезает до разбора, наш сканер — нет, и скобки внутри комментария
   сбили бы его. */
static int has_comments(const xjson_span_t *v)
{
    int in_str = 0;
    for (size_t i = 0; i < v->len; i++) {
        char c = v->ptr[i];
        if (in_str) {
            if (c == '\\') i++;
            else if (c == '"') in_str = 0;
            continue;
        }
        if (c == '"') in_str = 1;
        else if (c == '/' && i + 1 < v->len && (v->ptr[i + 1] == '/' || v->ptr[i + 1] == '*'))
            return 1;
    }
    return 0;
}

/* Строковое поле объекта: значение без кавычек, без раскрытия
   экранирования (для тегов и протоколов этого достаточно). */
static int obj_str(const xjson_span_t *obj, const char *name, char *dst, size_t size)
{
    const char *p = obj->ptr + 1, *end = obj->ptr + obj->len;
    xjson_span_t k, v;
    while (xjson_next_member(&p, end, &k, &v) == 1) {
        if (!span_is(&k, name)) continue;
        if (v.len < 2 || *v.ptr != '"') return 0;
        size_t n = v.len - 2;
        if (n >= size) n = size - 1;
        memcpy(dst, v.ptr + 1, n);
        dst[n] = '\0';
        return 1;
    }
    return 0;
}

static int is_tunnel_protocol(const char *p)
{
    return !strcmp(p, "vless") || !strcmp(p, "vmess") || !strcmp(p, "trojan") ||
           !strcmp(p, "shadowsocks");
}

static void fail(char *err, size_t err_size, const char *why)
{
    if (err && err_size) str_copy(err, err_size, why);
}

/* outbounds панели: проверка каждого и имя первого серверного. */
static int check_outbounds(const xjson_span_t *arr, char *first_proxy, size_t size,
                           char *err, size_t err_size)
{
    first_proxy[0] = '\0';
    if (arr->len < 2 || *arr->ptr != '[') { fail(err, err_size, "outbounds не массив"); return -1; }
    const char *q = xjson_ws(arr->ptr + 1, arr->ptr + arr->len), *qe = arr->ptr + arr->len;
    int n = 0;
    while (q < qe && *q != ']') {
        if (*q == ',') { q = xjson_ws(q + 1, qe); continue; }
        const char *e = xjson_skip_value(q, qe);
        if (!e) { fail(err, err_size, "outbounds битый"); return -1; }
        xjson_span_t ob = { q, (size_t)(e - q) };
        if (*q != '{') { fail(err, err_size, "outbound не объект"); return -1; }

        char proto[32] = "";
        obj_str(&ob, "protocol", proto, sizeof(proto));
        for (char *c = proto; *c; c++) if (*c >= 'A' && *c <= 'Z') *c = (char)(*c + 32);
        if (!is_tunnel_protocol(proto) && strcmp(proto, "freedom") && strcmp(proto, "blackhole")) {
            fail(err, err_size, "outbound с недопустимым протоколом"); return -1;
        }
        static const char *banned[] = { "\"reverse\"", "\"sockopt\"", "\"redirect\"",
                                        "\"dialerproxy\"", "\"proxysettings\"", NULL };
        for (int i = 0; banned[i]; i++)
            if (span_has(&ob, banned[i])) { fail(err, err_size, "outbound с запрещённым полем"); return -1; }

        if (!first_proxy[0] && is_tunnel_protocol(proto)) {
            char tag[64] = "";
            if (obj_str(&ob, "tag", tag, sizeof(tag))) str_copy(first_proxy, size, tag);
        }
        n++;
        q = xjson_ws(e, qe);
    }
    if (!n) { fail(err, err_size, "outbounds пуст"); return -1; }
    if (!first_proxy[0]) { fail(err, err_size, "в outbounds нет серверного с тегом"); return -1; }
    return 0;
}

/* routing панели: правила без geo и webhook, балансировщики как есть,
   и замыкающее правило с нашего входа. */
static int copy_routing(json_t *j, const xjson_span_t *routing, const char *first_proxy,
                        char *err, size_t err_size)
{
    char first_balancer[64] = "";
    const char *p = routing->ptr + 1, *end = routing->ptr + routing->len;
    xjson_span_t k, v;
    int rc;

    /* Первый проход: тег первого балансировщика и проверки. */
    while ((rc = xjson_next_member(&p, end, &k, &v)) == 1) {
        if (span_is(&k, "balancers") && v.len >= 2 && *v.ptr == '[') {
            const char *q = xjson_ws(v.ptr + 1, v.ptr + v.len);
            if (*q == '{') {
                const char *e = xjson_skip_value(q, v.ptr + v.len);
                if (e) { xjson_span_t b = { q, (size_t)(e - q) }; obj_str(&b, "tag", first_balancer, sizeof(first_balancer)); }
            }
        }
        if (span_is(&k, "rules") && span_has(&v, "\"webhook\"")) {
            fail(err, err_size, "правило с webhook"); return -1;
        }
    }
    if (rc < 0) { fail(err, err_size, "routing битый"); return -1; }

    json_key(j, "routing");
    json_obj_open(j);
    int had_rules = 0;
    p = routing->ptr + 1;
    while ((rc = xjson_next_member(&p, end, &k, &v)) == 1) {
        if (span_is(&k, "domainstrategy") || span_is(&k, "domainmatcher") || span_is(&k, "balancers")) {
            char key[32];
            memcpy(key, k.ptr, k.len); key[k.len] = '\0';
            json_key(j, key);
            json_rawn(j, v.ptr, v.len);
            continue;
        }
        if (!span_is(&k, "rules") || v.len < 2 || *v.ptr != '[') continue;   /* прочее не нужно */
        had_rules = 1;
        json_key(j, "rules");
        json_arr_open(j);
        const char *q = xjson_ws(v.ptr + 1, v.ptr + v.len), *qe = v.ptr + v.len;
        while (q < qe && *q != ']') {
            if (*q == ',') { q = xjson_ws(q + 1, qe); continue; }
            const char *e = xjson_skip_value(q, qe);
            if (!e) return -1;
            xjson_span_t rule = { q, (size_t)(e - q) };
            if (!span_has(&rule, "geoip:") && !span_has(&rule, "geosite:") &&
                !span_has(&rule, "\"ext:"))
                json_rawn(j, rule.ptr, rule.len);
            q = xjson_ws(e, qe);
        }
        /* Замыкающее правило — наше. */
        json_obj_open(j);
        json_kv_str(j, "type", "field");
        json_key(j, "inboundTag");
        json_arr_open(j); json_str(j, TAG_SOCKS_IN); json_arr_close(j);
        if (first_balancer[0]) json_kv_str(j, "balancerTag", first_balancer);
        else                   json_kv_str(j, "outboundTag", first_proxy);
        json_obj_close(j);
        json_arr_close(j);
    }
    if (rc < 0) return -1;
    if (!had_rules) {
        json_key(j, "rules");
        json_arr_open(j);
        json_obj_open(j);
        json_kv_str(j, "type", "field");
        json_key(j, "inboundTag");
        json_arr_open(j); json_str(j, TAG_SOCKS_IN); json_arr_close(j);
        if (first_balancer[0]) json_kv_str(j, "balancerTag", first_balancer);
        else                   json_kv_str(j, "outboundTag", first_proxy);
        json_obj_close(j);
        json_arr_close(j);
    }
    json_obj_close(j);
    return 0;
}

/* burstObservatory панели без pingConfig.connectivity: по нему ядро при
   неудаче пробы ходит на URL панели напрямую, минуя туннель. Остальное
   (destination, interval, sampling, timeout) — как есть. */
static void copy_object_without(json_t *j, const xjson_span_t *obj, const char *skip);

static void copy_burst(json_t *j, const xjson_span_t *burst)
{
    json_key(j, "burstObservatory");
    json_obj_open(j);
    const char *p = burst->ptr + 1, *end = burst->ptr + burst->len;
    xjson_span_t k, v;
    while (xjson_next_member(&p, end, &k, &v) == 1) {
        char key[64];
        if (k.len >= sizeof(key)) continue;
        memcpy(key, k.ptr, k.len); key[k.len] = '\0';
        if (span_is(&k, "pingconfig") && v.len >= 2 && *v.ptr == '{') {
            json_key(j, "pingConfig");
            copy_object_without(j, &v, "connectivity");
            continue;
        }
        json_key(j, key);
        json_rawn(j, v.ptr, v.len);
    }
    json_obj_close(j);
}

static void copy_object_without(json_t *j, const xjson_span_t *obj, const char *skip)
{
    json_obj_open(j);
    const char *p = obj->ptr + 1, *end = obj->ptr + obj->len;
    xjson_span_t k, v;
    while (xjson_next_member(&p, end, &k, &v) == 1) {
        char key[64];
        if (k.len >= sizeof(key) || span_is(&k, skip)) continue;
        memcpy(key, k.ptr, k.len); key[k.len] = '\0';
        json_key(j, key);
        json_rawn(j, v.ptr, v.len);
    }
    json_obj_close(j);
}

int xraycfg_build_from_json(const xjson_item_t *it, const xraycfg_opts_t *o,
                            char *buf, size_t size, char *err, size_t err_size)
{
    if (err && err_size) err[0] = '\0';
    if (!it || !o || !buf || !it->whole.ptr || it->whole.len < 2) { fail(err, err_size, "пустой конфиг"); return -1; }
    if (has_comments(&it->whole)) { fail(err, err_size, "в конфиге комментарии"); return -1; }

    /* Первый проход: найти куски и отсеять дубликаты. */
    xjson_span_t outbounds = { NULL, 0 }, routing = { NULL, 0 },
                 observ = { NULL, 0 }, burst = { NULL, 0 };
    const char *seen[64]; size_t seen_len[64]; int nseen = 0;
    const char *p = it->whole.ptr + 1, *end = it->whole.ptr + it->whole.len;
    xjson_span_t k, v;
    int rc;
    while ((rc = xjson_next_member(&p, end, &k, &v)) == 1) {
        for (int i = 0; i < nseen; i++) {
            xjson_span_t prev = { seen[i], seen_len[i] };
            char name[64];
            if (k.len >= sizeof(name)) { fail(err, err_size, "слишком длинный ключ"); return -1; }
            memcpy(name, k.ptr, k.len); name[k.len] = '\0';
            for (char *c = name; *c; c++) if (*c >= 'A' && *c <= 'Z') *c = (char)(*c + 32);
            if (span_is(&prev, name)) { fail(err, err_size, "повторяющийся ключ"); return -1; }
        }
        if (nseen < 64) { seen[nseen] = k.ptr; seen_len[nseen] = k.len; nseen++; }

        if      (span_is(&k, "outbounds"))        outbounds = v;
        else if (span_is(&k, "routing"))          routing = v;
        else if (span_is(&k, "observatory"))      observ = v;
        else if (span_is(&k, "burstobservatory")) burst = v;
        /* всё остальное — мимо */
    }
    if (rc < 0) { fail(err, err_size, "конфиг битый"); return -1; }
    if (!outbounds.ptr) { fail(err, err_size, "нет outbounds"); return -1; }

    char first_proxy[64] = "";
    if (check_outbounds(&outbounds, first_proxy, sizeof(first_proxy), err, err_size) != 0) return -1;

    json_t j;
    json_init(&j, buf, size);
    json_obj_open(&j);
    build_log(&j, o);

    json_key(&j, "inbounds");
    json_arr_open(&j);
    build_inbound(&j, o);
    json_arr_close(&j);

    json_key(&j, "outbounds");
    json_rawn(&j, outbounds.ptr, outbounds.len);

    if (routing.ptr && routing.len >= 2 && *routing.ptr == '{') {
        if (copy_routing(&j, &routing, first_proxy, err, err_size) != 0) return -1;
    } else {
        json_key(&j, "routing");
        json_obj_open(&j);
        json_key(&j, "rules");
        json_arr_open(&j);
        json_obj_open(&j);
        json_kv_str(&j, "type", "field");
        json_key(&j, "inboundTag");
        json_arr_open(&j); json_str(&j, TAG_SOCKS_IN); json_arr_close(&j);
        json_kv_str(&j, "outboundTag", first_proxy);
        json_obj_close(&j);
        json_arr_close(&j);
        json_obj_close(&j);
    }

    if (observ.ptr && observ.len >= 2 && *observ.ptr == '{') {
        json_key(&j, "observatory");
        json_rawn(&j, observ.ptr, observ.len);
    }
    if (burst.ptr && burst.len >= 2 && *burst.ptr == '{')
        copy_burst(&j, &burst);

    json_obj_close(&j);
    if (json_done(&j) != 0) { fail(err, err_size, "не поместилось"); return -1; }
    return 0;
}
