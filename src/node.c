#include "node.h"
#include "url.h"
#include "util.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>

/* Читает параметр запроса в поле фиксированного размера.
   Отсутствие параметра — не ошибка: поле остаётся пустым. Усечение —
   ошибка: молча обрезанный ключ или путь выглядит как настоящий и
   ломается уже на сервере. Имя усечённого параметра запоминаем, чтобы
   назвать его в отказе. */
static const char *g_truncated;

static void q(const url_t *u, const char *key, char *dst, unsigned dst_size)
{
    char tmp[URL_QUERY_MAX];
    if (url_query_get(u, key, tmp, sizeof(tmp)) == 1) {
        if (str_copy(dst, dst_size, tmp) != 0 && !g_truncated) g_truncated = key;
    }
}

static void fail(char *err, unsigned err_size, const char *msg)
{
    if (err && err_size) str_copy(err, err_size, msg);
}

int node_from_link(const char *link, node_t *n, char *err, unsigned err_size)
{
    if (!link || !n) {
        fail(err, err_size, "пустая ссылка");
        return -1;
    }

    memset(n, 0, sizeof(*n));

    url_t u;
    if (url_parse(link, &u) != 0) {
        fail(err, err_size, "не похоже на ссылку вида схема://...");
        return -1;
    }

    if (strcmp(u.scheme, "vless") != 0) {
        fail(err, err_size, "поддерживается только vless://");
        return -1;
    }
    str_copy(n->protocol, sizeof(n->protocol), "vless");

    if (!u.user[0]) {
        fail(err, err_size, "в ссылке нет идентификатора пользователя");
        return -1;
    }
    str_copy(n->id, sizeof(n->id), u.user);

    str_copy(n->address, sizeof(n->address), u.host);
    n->address_is_ipv6 = u.host_is_ipv6;

    /* Порт обязателен: у VLESS нет общепринятого значения по умолчанию,
       и подстановка 443 молча увела бы трафик не туда. */
    if (u.port <= 0) {
        fail(err, err_size, "в ссылке не указан порт");
        return -1;
    }
    n->port = u.port;

    g_truncated = NULL;

    q(&u, "flow",       n->flow,        sizeof(n->flow));
    q(&u, "encryption", n->encryption,  sizeof(n->encryption));
    q(&u, "type",       n->network,     sizeof(n->network));
    q(&u, "security",   n->security,    sizeof(n->security));
    q(&u, "headerType", n->header_type, sizeof(n->header_type));

    q(&u, "sni",  n->sni,  sizeof(n->sni));
    q(&u, "alpn", n->alpn, sizeof(n->alpn));
    q(&u, "fp",   n->fingerprint, sizeof(n->fingerprint));

    q(&u, "pbk", n->public_key, sizeof(n->public_key));
    q(&u, "sid", n->short_id,   sizeof(n->short_id));
    q(&u, "spx", n->spider_x,   sizeof(n->spider_x));

    q(&u, "path",        n->path,         sizeof(n->path));
    q(&u, "host",        n->host,         sizeof(n->host));
    q(&u, "mode",        n->mode,         sizeof(n->mode));
    q(&u, "serviceName", n->service_name, sizeof(n->service_name));
    q(&u, "authority",   n->authority,    sizeof(n->authority));

    if (g_truncated) {
        char msg[96];
        snprintf(msg, sizeof(msg), "параметр %s слишком длинный", g_truncated);
        fail(err, err_size, msg);
        return -1;
    }

    char insecure[16];
    if (url_query_get(&u, "allowInsecure", insecure, sizeof(insecure)) == 1)
        n->allow_insecure = parse_bool(insecure, 0);

    /* Значения по умолчанию — только там, где у Xray они однозначны. */
    if (!n->network[0])    str_copy(n->network, sizeof(n->network), "tcp");

    /* Ядро переименовало tcp в raw; панели пишут и так, и так. */
    if (!strcmp(n->network, "raw")) str_copy(n->network, sizeof(n->network), "tcp");

    /* Что умеем собирать. Незнакомая сеть раньше уходила в конфиг как
       есть: -test проходил, а соединение не устанавливалось — kcp без
       seed, quic и прочее. Лучше честный отказ. */
    if (strcmp(n->network, "tcp") && strcmp(n->network, "ws") &&
        strcmp(n->network, "grpc") && strcmp(n->network, "xhttp") &&
        strcmp(n->network, "splithttp") && strcmp(n->network, "httpupgrade")) {
        char msg[96];
        snprintf(msg, sizeof(msg), "транспорт %s не поддерживается", n->network);
        fail(err, err_size, msg);
        return -1;
    }

    /* Vision работает только поверх голого tcp. С ws/grpc/xhttp -test
       проходил, а каждое соединение падало с «XTLS only supports TLS
       and REALITY directly». Панели такое генерируют. */
    if (n->flow[0] && (strcmp(n->network, "tcp") != 0 ||
                       !strcmp(n->header_type, "http") ||
                       (strcmp(n->security, "tls") && strcmp(n->security, "reality")))) {
        n->flow[0]      = '\0';
        n->flow_dropped = 1;
    }

    /* Незнакомый отпечаток uTLS ядро отвергает на -test, и одна ссылка
       валила бы весь конфиг. Заменяем на умолчание ядра и помечаем. */
    if (n->fingerprint[0]) {
        static const char *known[] = { "chrome", "firefox", "safari", "ios", "android",
                                       "edge", "360", "qq", "random", "randomized",
                                       "randomizednoalpn", NULL };
        int ok = 0;
        for (int i = 0; known[i]; i++) if (!strcasecmp(n->fingerprint, known[i])) ok = 1;
        if (!ok) { str_copy(n->fingerprint, sizeof(n->fingerprint), "chrome"); n->fp_fixed = 1; }
    }
    if (!n->security[0])   str_copy(n->security, sizeof(n->security), "none");
    if (!n->encryption[0]) str_copy(n->encryption, sizeof(n->encryption), "none");

    /* SNI не подставляем из адреса: при Reality это разные вещи, и подмена
       ломает соединение, а при обычном TLS Xray сам возьмёт адрес. */

    if (strcmp(n->security, "reality") == 0 && !n->public_key[0]) {
        fail(err, err_size, "reality без публичного ключа pbk");
        return -1;
    }
    /* Без sni ядро подставит адрес сервера, и рукопожатие с Reality не
       сойдётся — а -test этого не видит. */
    if (strcmp(n->security, "reality") == 0 && !n->sni[0]) {
        fail(err, err_size, "reality без sni");
        return -1;
    }

    if (u.fragment[0]) {
        str_copy(n->tag, sizeof(n->tag), u.fragment);
    } else {
        /* Адрес длиннее тега, поэтому сначала укорачиваем его сами:
           так обрезка становится осознанной, а не побочным эффектом
           snprintf. Запас в 8 байт — под ":" и номер порта. */
        char addr[NODE_TAG_MAX - 8];
        str_copy(addr, sizeof(addr), n->address);
        snprintf(n->tag, sizeof(n->tag), "%s:%d", addr, n->port);
    }

    return 0;
}
