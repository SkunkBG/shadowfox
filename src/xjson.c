#include "xjson.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *xjson_ws(const char *p, const char *end)
{
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) p++;
    return p;
}

static const char *skip_string(const char *p, const char *end)
{
    if (p >= end || *p != '"') return NULL;
    p++;
    while (p < end) {
        if (*p == '\\') { p += 2; continue; }
        if (*p == '"')  return p + 1;
        p++;
    }
    return NULL;
}

const char *xjson_skip_value(const char *p, const char *end)
{
    p = xjson_ws(p, end);
    if (p >= end) return NULL;

    if (*p == '"') return skip_string(p, end);

    if (*p == '{' || *p == '[') {
        int depth = 0;
        while (p < end) {
            if (*p == '"') { p = skip_string(p, end); if (!p) return NULL; continue; }
            if (*p == '{' || *p == '[') depth++;
            else if (*p == '}' || *p == ']') { depth--; if (depth == 0) return p + 1; }
            p++;
        }
        return NULL;
    }

    /* число либо литерал */
    const char *s = p;
    while (p < end && *p != ',' && *p != '}' && *p != ']' &&
           *p != ' ' && *p != '\n' && *p != '\r' && *p != '\t')
        p++;
    return p > s ? p : NULL;
}

int xjson_next_member(const char **pp, const char *end,
                      xjson_span_t *key, xjson_span_t *val)
{
    const char *p = xjson_ws(*pp, end);
    if (p >= end) return -1;
    if (*p == ',') p = xjson_ws(p + 1, end);
    if (p >= end) return -1;
    if (*p == '}') { *pp = p; return 0; }
    if (*p != '"') return -1;

    const char *ke = skip_string(p, end);
    if (!ke) return -1;
    key->ptr = p + 1;
    key->len = (size_t)(ke - p - 2);

    p = xjson_ws(ke, end);
    if (p >= end || *p != ':') return -1;
    p = xjson_ws(p + 1, end);

    const char *ve = xjson_skip_value(p, end);
    if (!ve) return -1;
    val->ptr = p;
    val->len = (size_t)(ve - p);
    *pp = ve;
    return 1;
}

static int key_is(const xjson_span_t *k, const char *name)
{
    return k->len == strlen(name) && !memcmp(k->ptr, name, k->len);
}

/* Строка JSON → UTF-8. \uXXXX, включая суррогатные пары: флаги стран
   в именах приходят и так. */
static unsigned hex4(const char *p)
{
    unsigned v = 0;
    for (int i = 0; i < 4; i++) {
        char c = p[i];
        v <<= 4;
        if (c >= '0' && c <= '9') v |= (unsigned)(c - '0');
        else if (c >= 'a' && c <= 'f') v |= (unsigned)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') v |= (unsigned)(c - 'A' + 10);
        else return 0xFFFFFFFFu;
    }
    return v;
}

static size_t put_utf8(char *dst, size_t size, size_t used, unsigned cp)
{
    char b[4];
    int  n;
    if (cp < 0x80)         { b[0] = (char)cp; n = 1; }
    else if (cp < 0x800)   { b[0] = (char)(0xC0 | (cp >> 6)); b[1] = (char)(0x80 | (cp & 0x3F)); n = 2; }
    else if (cp < 0x10000) { b[0] = (char)(0xE0 | (cp >> 12)); b[1] = (char)(0x80 | ((cp >> 6) & 0x3F)); b[2] = (char)(0x80 | (cp & 0x3F)); n = 3; }
    else                   { b[0] = (char)(0xF0 | (cp >> 18)); b[1] = (char)(0x80 | ((cp >> 12) & 0x3F)); b[2] = (char)(0x80 | ((cp >> 6) & 0x3F)); b[3] = (char)(0x80 | (cp & 0x3F)); n = 4; }
    if (used + (size_t)n >= size) return used;
    memcpy(dst + used, b, (size_t)n);
    return used + (size_t)n;
}

static void unescape(const xjson_span_t *s, char *dst, size_t size)
{
    size_t used = 0;
    const char *p = s->ptr + 1, *end = s->ptr + s->len - 1;   /* без кавычек */
    if (s->len < 2 || *s->ptr != '"') { dst[0] = '\0'; return; }
    while (p < end && used + 1 < size) {
        if (*p != '\\') { dst[used++] = *p++; continue; }
        if (p + 1 >= end) break;
        char c = p[1];
        p += 2;
        switch (c) {
        case 'n': dst[used++] = '\n'; break;
        case 't': dst[used++] = '\t'; break;
        case 'r': dst[used++] = '\r'; break;
        case 'b': case 'f': break;
        case 'u': {
            if (p + 4 > end) { p = end; break; }
            unsigned cp = hex4(p);
            p += 4;
            if (cp == 0xFFFFFFFFu) break;
            if (cp >= 0xD800 && cp <= 0xDBFF && p + 6 <= end && p[0] == '\\' && p[1] == 'u') {
                unsigned lo = hex4(p + 2);
                if (lo >= 0xDC00 && lo <= 0xDFFF) {
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                    p += 6;
                }
            }
            used = put_utf8(dst, size, used, cp);
            break;
        }
        default: dst[used++] = c; break;
        }
    }
    dst[used] = '\0';
    str_trim(dst);
}

int xjson_looks_like(const char *text)
{
    if (!text) return 0;
    const char *p = xjson_ws(text, text + strlen(text));
    return *p == '[' || *p == '{';
}

static int add_item(xjson_t *x, const char *p, const char *end)
{
    if (x->count >= XJSON_MAX) return -1;
    xjson_item_t *it = &x->items[x->count];
    memset(it, 0, sizeof(*it));

    const char *q = p + 1;
    xjson_span_t k, v;
    int rc, have_out = 0;
    while ((rc = xjson_next_member(&q, end, &k, &v)) == 1) {
        if (key_is(&k, "remarks")) unescape(&v, it->remarks, sizeof(it->remarks));
        else if (key_is(&k, "outbounds")) have_out = 1;
    }
    if (rc < 0) return -1;
    if (!have_out) { x->skipped++; return 0; }

    it->whole.ptr = p;
    it->whole.len = (size_t)(end - p);
    if (!it->remarks[0]) snprintf(it->remarks, sizeof(it->remarks), "конфиг %d", x->count + 1);
    x->count++;
    return 1;
}

int xjson_parse(const char *text, xjson_t *x)
{
    if (!text || !x) return -1;
    memset(x, 0, sizeof(*x));

    const char *end = text + strlen(text);
    const char *p   = xjson_ws(text, end);

    if (*p == '{') {
        const char *e = xjson_skip_value(p, end);
        if (!e) return -1;
        return add_item(x, p, e) < 0 ? -1 : x->count;
    }
    if (*p != '[') return -1;

    p = xjson_ws(p + 1, end);
    while (p < end && *p != ']') {
        if (*p == ',') { p = xjson_ws(p + 1, end); continue; }
        const char *e = xjson_skip_value(p, end);
        if (!e) return -1;
        if (*p == '{' && add_item(x, p, e) < 0) break;   /* места нет — остальные мимо */
        p = xjson_ws(e, end);
    }
    return x->count;
}

/* Порты из "port": N внутри outbounds. Свои входы сюда не попадают:
   ищем только в этом куске. */
int xjson_ports(const xjson_item_t *it, int *ports, int max)
{
    if (!it || !ports || max <= 0) return 0;
    int n = 0;

    const char *p = it->whole.ptr + 1, *end = it->whole.ptr + it->whole.len;
    xjson_span_t k, v;
    while (xjson_next_member(&p, end, &k, &v) == 1) {
        if (!key_is(&k, "outbounds")) continue;
        const char *q = v.ptr, *qe = v.ptr + v.len;
        while ((q = memmem(q, (size_t)(qe - q), "\"port\"", 6)) != NULL) {
            q += 6;
            q = xjson_ws(q, qe);
            if (q < qe && *q == ':') {
                q = xjson_ws(q + 1, qe);
                if (q < qe && *q >= '0' && *q <= '9') {
                    int port = atoi(q), dup = 0;
                    for (int i = 0; i < n; i++) if (ports[i] == port) dup = 1;
                    if (!dup && port > 0 && port < 65536 && n < max) ports[n++] = port;
                }
            }
        }
        break;
    }
    return n;
}
