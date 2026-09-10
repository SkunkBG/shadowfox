#include "jsonw.h"

#include <stdio.h>
#include <string.h>

static void put(json_t *j, const char *s, size_t n)
{
    if (j->failed) return;
    if (j->len + n >= j->size) { j->failed = 1; return; }
    memcpy(j->buf + j->len, s, n);
    j->len += n;
    j->buf[j->len] = '\0';
}

static void put_s(json_t *j, const char *s)
{
    put(j, s, strlen(s));
}

/* Разделитель перед очередным элементом текущего уровня. */
static void sep(json_t *j)
{
    if (j->need_comma) put_s(j, ",");
    j->need_comma = 1;
}

void json_init(json_t *j, char *buf, size_t size)
{
    memset(j, 0, sizeof(*j));
    j->buf  = buf;
    j->size = size;
    if (size) buf[0] = '\0';
}

static void open_scope(json_t *j, const char *brace)
{
    sep(j);
    put_s(j, brace);
    j->depth++;
    j->need_comma = 0;
}

static void close_scope(json_t *j, const char *brace)
{
    put_s(j, brace);
    j->depth--;
    j->need_comma = 1;
}

void json_obj_open(json_t *j)  { open_scope(j, "{"); }
void json_obj_close(json_t *j) { close_scope(j, "}"); }
void json_arr_open(json_t *j)  { open_scope(j, "["); }
void json_arr_close(json_t *j) { close_scope(j, "]"); }

static void write_escaped(json_t *j, const char *s)
{
    put_s(j, "\"");
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        switch (*p) {
        case '"':  put_s(j, "\\\"");  break;
        case '\\': put_s(j, "\\\\");  break;
        case '\n': put_s(j, "\\n");   break;
        case '\r': put_s(j, "\\r");   break;
        case '\t': put_s(j, "\\t");   break;
        case '\b': put_s(j, "\\b");   break;
        case '\f': put_s(j, "\\f");   break;
        default:
            if (*p < 0x20) {
                /* Управляющие символы обязаны быть экранированы, иначе
                   получится JSON, который xray отвергнет. */
                char esc[16];
                snprintf(esc, sizeof(esc), "\\u%04x", *p);
                put_s(j, esc);
            } else {
                /* UTF-8 пропускаем байтами как есть: он валиден в JSON. */
                put(j, (const char *)p, 1);
            }
        }
    }
    put_s(j, "\"");
}

void json_key(json_t *j, const char *key)
{
    sep(j);
    write_escaped(j, key);
    put_s(j, ":");
    j->need_comma = 0;
}

void json_str(json_t *j, const char *value)
{
    sep(j);
    write_escaped(j, value ? value : "");
}

void json_int(json_t *j, long value)
{
    char num[32];
    snprintf(num, sizeof(num), "%ld", value);
    sep(j);
    put_s(j, num);
}

void json_bool(json_t *j, int value)
{
    sep(j);
    put_s(j, value ? "true" : "false");
}

void json_raw(json_t *j, const char *raw)
{
    sep(j);
    put_s(j, raw ? raw : "null");
}

void json_rawn(json_t *j, const char *raw, size_t len)
{
    sep(j);
    if (raw && len) put(j, raw, len);
    else put_s(j, "null");
}

void json_kv_str(json_t *j, const char *key, const char *value)
{
    json_key(j, key);
    json_str(j, value);
}

void json_kv_int(json_t *j, const char *key, long value)
{
    json_key(j, key);
    json_int(j, value);
}

void json_kv_bool(json_t *j, const char *key, int value)
{
    json_key(j, key);
    json_bool(j, value);
}

void json_kv_str_list(json_t *j, const char *key, const char *value, char sep_ch)
{
    json_key(j, key);
    json_arr_open(j);

    if (value && *value) {
        const char *p = value;
        while (*p) {
            const char *next = strchr(p, sep_ch);
            size_t      len  = next ? (size_t)(next - p) : strlen(p);

            char item[256];
            if (len >= sizeof(item)) { j->failed = 1; break; }
            memcpy(item, p, len);
            item[len] = '\0';

            if (item[0]) json_str(j, item);

            if (!next) break;
            p = next + 1;
        }
    }

    json_arr_close(j);
}

int json_done(const json_t *j)
{
    if (j->failed)  return -1;
    if (j->depth)   return -1;
    return 0;
}
