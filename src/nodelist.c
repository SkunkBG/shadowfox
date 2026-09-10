#include "nodelist.h"
#include "base64.h"
#include "util.h"

#include <stdio.h>
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

int nodelist_add_link(nodelist_t *l, const char *link,
                      char *err, unsigned err_size)
{
    if (!l) return -1;

    if (l->count >= NODELIST_MAX) {
        if (err && err_size) str_copy(err, err_size, "слишком много узлов");
        return -1;
    }

    node_t n;
    if (node_from_link(link, &n, err, err_size) != 0) return -1;

    make_tag_unique(l, &n);
    l->items[l->count++] = n;
    return 0;
}

static int add_lines(nodelist_t *l, const char *text)
{
    int added = 0;

    const char *p = text;
    while (*p) {
        const char *nl  = strchr(p, '\n');
        size_t      len = nl ? (size_t)(nl - p) : strlen(p);

        char line[8192];   /* VLESS Encryption даёт ссылки за 1,5 КБ */
        if (len < sizeof(line)) {
            memcpy(line, p, len);
            line[len] = '\0';

            char *s = str_trim(line);
            if (*s && *s != '#') {
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
