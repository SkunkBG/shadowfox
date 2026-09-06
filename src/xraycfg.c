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
    /* Фрагментация и шум выключены по умолчанию. Рабочая установка на
       Keenetic обходится без них, а стоят они задержки и процессора.
       Навязывать то, чего нет в работающей конфигурации, неправильно:
       включаются флагом --fragment, когда провайдер этого требует. */
    o->fragment   = 0;
    o->noise      = 0;
    o->sniffing   = 1;
    o->log_level  = "warning";
    o->probe_url  = "https://www.gstatic.com/generate_204";
    o->probe_interval = "5m";
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
    json_kv_str(j, "auth", "noauth");
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
        json_kv_str(j, "fingerprint",
                    n->fingerprint[0] ? n->fingerprint : "chrome");
        json_obj_close(j);
    } else if (strcmp(n->security, "tls") == 0) {
        json_key(j, "tlsSettings");
        json_obj_open(j);
        if (n->sni[0]) json_kv_str(j, "serverName", n->sni);
        json_kv_str(j, "fingerprint",
                    n->fingerprint[0] ? n->fingerprint : "chrome");
        /* alpn пишем только если он пришёл в ссылке. neofit прописывал
           ["h2","http/1.1"] всегда, рассогласуя ALPN с отпечатком uTLS. */
        if (n->alpn[0]) json_kv_str_list(j, "alpn", n->alpn, ',');
        if (n->allow_insecure) json_kv_bool(j, "allowInsecure", 1);
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
        json_obj_close(j);
    } else if (strcmp(n->network, "xhttp") == 0 ||
               strcmp(n->network, "splithttp") == 0) {
        json_key(j, "xhttpSettings");
        json_obj_open(j);
        json_kv_str(j, "path", n->path[0] ? n->path : "/");
        if (n->host[0]) json_kv_str(j, "host", n->host);
        json_obj_close(j);
    } else if (strcmp(n->network, "tcp") == 0 &&
               strcmp(n->header_type, "http") == 0) {
        json_key(j, "tcpSettings");
        json_obj_open(j);
        json_key(j, "header");
        json_obj_open(j);
        json_kv_str(j, "type", "http");
        json_obj_close(j);
        json_obj_close(j);
    }

    /* Фрагментация делается отдельным исходящим, а трафик узла
       направляется через него. Своего поля fragment у vless нет. */
    if (o->fragment) {
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
    json_obj_open(j);
    json_kv_str(j, "tag", TAG_FRAGMENT);
    json_kv_str(j, "protocol", "freedom");

    json_key(j, "settings");
    json_obj_open(j);

    json_key(j, "fragment");
    json_obj_open(j);
    json_kv_str(j, "packets", "tlshello");
    json_kv_str(j, "length", "100-200");
    json_kv_str(j, "interval", "10-20");
    json_obj_close(j);

    if (o->noise) {
        json_key(j, "noises");
        json_arr_open(j);
        json_obj_open(j);
        json_kv_str(j, "type", "rand");
        json_kv_str(j, "packet", "10-20");
        json_kv_str(j, "delay", "10-16");
        json_obj_close(j);
        json_arr_close(j);
    }

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

    json_key(&j, "log");
    json_obj_open(&j);
    json_kv_str(&j, "loglevel", o->log_level ? o->log_level : "warning");
    json_obj_close(&j);

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
    if (o->fragment) build_fragment_outbound(&j, o);

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
