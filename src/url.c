#include "url.h"
#include "util.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

static int hex_val(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int url_pct_decode(const char *in, char *out, size_t out_size)
{
    if (!in || !out || out_size == 0) return -1;

    size_t o = 0;
    for (size_t i = 0; in[i]; i++) {
        if (o + 1 >= out_size) { out[o] = '\0'; return -1; }

        if (in[i] == '%') {
            int hi = hex_val((unsigned char)in[i + 1]);
            int lo = hi < 0 ? -1 : hex_val((unsigned char)in[i + 2]);
            if (hi >= 0 && lo >= 0) {
                out[o++] = (char)((hi << 4) | lo);
                i += 2;
                continue;
            }
            /* Битая последовательность — оставляем '%' как обычный символ,
               иначе ссылка с процентом в имени сервера отвалится целиком. */
        }
        out[o++] = in[i];
    }

    out[o] = '\0';
    return 0;
}

int url_parse(const char *s, url_t *u)
{
    if (!s || !u) return -1;
    memset(u, 0, sizeof(*u));

    const char *sep = strstr(s, "://");
    if (!sep || sep == s) return -1;

    size_t scheme_len = (size_t)(sep - s);
    if (scheme_len >= sizeof(u->scheme)) return -1;
    for (size_t i = 0; i < scheme_len; i++)
        u->scheme[i] = (char)tolower((unsigned char)s[i]);
    u->scheme[scheme_len] = '\0';

    const char *rest = sep + 3;

    /* Фрагмент отрезаем первым: в нём может быть что угодно, включая '?'. */
    const char *hash = strchr(rest, '#');
    if (hash) {
        char raw[URL_FRAG_MAX];
        if (str_copy(raw, sizeof(raw), hash + 1) != 0) return -1;
        if (url_pct_decode(raw, u->fragment, sizeof(u->fragment)) != 0) return -1;
    }

    size_t rest_len = hash ? (size_t)(hash - rest) : strlen(rest);

    char body[URL_HOST_MAX + URL_USER_MAX + URL_PATH_MAX + URL_QUERY_MAX];
    if (rest_len >= sizeof(body)) return -1;
    memcpy(body, rest, rest_len);
    body[rest_len] = '\0';

    char *qmark = strchr(body, '?');
    if (qmark) {
        *qmark = '\0';
        if (str_copy(u->query, sizeof(u->query), qmark + 1) != 0) return -1;
    }

    /* '/' ищем после того, как отрезали query: путь идёт до него. */
    char *slash = strchr(body, '/');
    if (slash) {
        /* Копируем до того, как обрежем: иначе читаем уже поставленный ноль. */
        if (str_copy(u->path, sizeof(u->path), slash) != 0) return -1;
        *slash = '\0';
    }

    char *hostpart = body;
    char *at       = strrchr(body, '@');   /* userinfo может содержать '@' */
    if (at) {
        *at = '\0';
        char raw[URL_USER_MAX];
        if (str_copy(raw, sizeof(raw), body) != 0) return -1;
        if (url_pct_decode(raw, u->user, sizeof(u->user)) != 0) return -1;
        hostpart = at + 1;
    }

    if (*hostpart == '[') {
        /* IPv6 в скобках: [2001:db8::1]:443 */
        char *close = strchr(hostpart, ']');
        if (!close) return -1;
        *close = '\0';
        if (str_copy(u->host, sizeof(u->host), hostpart + 1) != 0) return -1;
        u->host_is_ipv6 = 1;
        if (close[1] == ':') u->port = atoi(close + 2);
    } else {
        char *colon = strrchr(hostpart, ':');
        if (colon) {
            *colon = '\0';
            u->port = atoi(colon + 1);
        }
        if (str_copy(u->host, sizeof(u->host), hostpart) != 0) return -1;
    }

    if (!u->host[0]) return -1;
    if (u->port < 0 || u->port > 65535) return -1;

    return 0;
}

int url_query_get(const url_t *u, const char *key, char *out, size_t out_size)
{
    if (!u || !key || !out || out_size == 0) return -1;
    out[0] = '\0';

    size_t key_len = strlen(key);
    const char *p  = u->query;

    while (*p) {
        const char *amp = strchr(p, '&');
        size_t      len = amp ? (size_t)(amp - p) : strlen(p);

        if (len > key_len && p[key_len] == '=' &&
            strncmp(p, key, key_len) == 0) {
            char raw[URL_QUERY_MAX];
            size_t vlen = len - key_len - 1;
            if (vlen >= sizeof(raw)) return -1;
            memcpy(raw, p + key_len + 1, vlen);
            raw[vlen] = '\0';
            return url_pct_decode(raw, out, out_size) == 0 ? 1 : -1;
        }

        if (!amp) break;
        p = amp + 1;
    }

    return 0;
}
