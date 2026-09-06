#include "nodelist.h"
#include "base64.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>

void nodelist_init(nodelist_t *l)
{
    memset(l, 0, sizeof(*l));
}

/* Теги идут в конфиг Xray и должны быть различимы: два узла с одним
   именем в подписке — обычное дело, а совпадение тегов ломает
   маршрутизацию молча. */
static void make_tag_unique(nodelist_t *l, node_t *n)
{
    /* Короче тега на запас под суффикс " #999": иначе добавление номера
       упирается в границу буфера. */
    char base[NODE_TAG_MAX - 8];
    str_copy(base, sizeof(base), n->tag);

    for (int attempt = 2; attempt < 1000; attempt++) {
        int clash = 0;
        for (int i = 0; i < l->count; i++) {
            if (strcmp(l->items[i].tag, n->tag) == 0) { clash = 1; break; }
        }
        if (!clash) return;
        snprintf(n->tag, sizeof(n->tag), "%s #%d", base, attempt);
    }
}

int nodelist_begin_server(nodelist_t *l, const char *name, int socks_port)
{
    if (!l || l->server_count >= NODELIST_SERVERS_MAX) return -1;

    int idx = l->server_count++;
    memset(&l->servers[idx], 0, sizeof(l->servers[idx]));
    str_copy(l->servers[idx].name, sizeof(l->servers[idx].name),
             (name && *name) ? name : "Сервер");
    l->servers[idx].socks_port = socks_port;
    return idx;
}

int nodelist_port(const nodelist_t *l, int server, int base)
{
    if (!l || server < 0 || server >= l->server_count) return base;
    if (l->servers[server].socks_port > 0) return l->servers[server].socks_port;
    return base + server;
}

int nodelist_add_link(nodelist_t *l, const char *link,
                      char *err, unsigned err_size)
{
    if (!l) return -1;

    if (l->count >= NODELIST_MAX) {
        if (err && err_size) str_copy(err, err_size, "слишком много узлов");
        return -1;
    }

    /* Ссылка до первого заголовка заводит сервер сама: файл из одних
       ссылок должен работать так же, как работал. */
    if (l->server_count == 0 && nodelist_begin_server(l, "Основной", 0) < 0) {
        if (err && err_size) str_copy(err, err_size, "слишком много серверов");
        return -1;
    }

    node_t n;
    if (node_from_link(link, &n, err, err_size) != 0) return -1;

    make_tag_unique(l, &n);
    l->owner[l->count] = (unsigned char)(l->server_count - 1);
    l->items[l->count++] = n;
    l->servers[l->server_count - 1].nodes++;
    return 0;
}

static int add_lines(nodelist_t *l, const char *text)
{
    int added = 0;

    const char *p = text;
    while (*p) {
        const char *nl  = strchr(p, '\n');
        size_t      len = nl ? (size_t)(nl - p) : strlen(p);

        char line[1024];
        if (len < sizeof(line)) {
            memcpy(line, p, len);
            line[len] = '\0';

            char *s = str_trim(line);

            size_t sl = strlen(s);
            if (sl > 2 && s[0] == '[' && s[sl - 1] == ']') {
                s[sl - 1] = '\0';
                if (nodelist_begin_server(l, str_trim(s + 1), 0) < 0)
                    l->skipped++;
            } else if (!strncasecmp(s, "socks", 5) && strchr(s, '=')) {
                int port = atoi(strchr(s, '=') + 1);
                if (l->server_count > 0 && port > 0 && port < 65536)
                    l->servers[l->server_count - 1].socks_port = port;
                else
                    l->skipped++;
            } else if (*s && *s != '#') {
                if (nodelist_add_link(l, s, NULL, 0) == 0) added++;
                else l->skipped++;
            }
        } else {
            l->skipped++;
        }

        if (!nl) break;
        p = nl + 1;
    }

    return added;
}

int nodelist_from_subscription(nodelist_t *l, const char *body)
{
    if (!l || !body) return -1;

    /* Подписки отдают либо base64 от списка ссылок, либо сам список.
       Различаем по результату: если после декодирования появилось
       "://", значит это был base64. */
    static char decoded[64 * 1024];
    long        n = base64_decode(body, decoded, sizeof(decoded));

    if (n > 0 && strstr(decoded, "://") != NULL)
        return add_lines(l, decoded);

    return add_lines(l, body);
}
