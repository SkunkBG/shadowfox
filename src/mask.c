#include "mask.h"
#include "util.h"

#include <stdio.h>
#include <string.h>

void mask_link(const char *in, char *out, size_t size)
{
    if (!out || !size) return;
    out[0] = '\0';
    if (!in) return;

    const char *scheme = strstr(in, "://");

    /* Без схемы это не ссылка, а тело подписки в base64 — и оно целиком
       есть ключ. Раньше такая строка копировалась как есть, и маска
       не маскировала ничего. */
    if (!scheme) {
        /* Комментарий — не секрет, base64 с решётки не начинается. */
        if (in[0] == '#')  str_copy(out, size, in);
        else if (in[0])    str_copy(out, size, MASK_MARK);
        return;
    }

    const char *rest = scheme + 3;
    const char *at   = strchr(rest, '@');
    const char *hash = strchr(rest, '#');

    /* Подписка целиком секрет: у неё вся ссылка — это доступ. */
    if (!at || (hash && at > hash)) {
        size_t head = (size_t)(rest - in);
        const char *slash = strchr(rest, '/');
        size_t host = slash ? (size_t)(slash - rest) : strlen(rest);
        snprintf(out, size, "%.*s%.*s/" MASK_MARK,
                 (int)head, in, (int)host, rest);
        return;
    }

    /* Ссылка на узел: прячем uuid и sid, остальное полезно видеть.
       Хвост собираем кусками через snprintf, а не правим на месте:
       прежний memmove сдвигал остаток на фиксированное смещение и при
       коротком sid= выезжал за буфер. */
    size_t      head = (size_t)(rest - in);
    const char *tail = at + 1;
    const char *sid  = strstr(tail, "sid=");

    if (!sid) {
        snprintf(out, size, "%.*s" MASK_MARK "@%s", (int)head, in, tail);
        return;
    }

    const char *val = sid + 4;
    const char *end = val;
    while (*end && *end != '&' && *end != '#') end++;

    snprintf(out, size, "%.*s" MASK_MARK "@%.*s****%s",
             (int)head, in, (int)(val - tail), tail, end);
}

void mask_nodes(const char *in, char *out, size_t size)
{
    if (!out || !size) return;

    size_t used = 0;
    out[0] = '\0';
    if (!in) return;

    const char *p = in;
    while (*p) {
        const char *nl  = strchr(p, '\n');
        size_t      len = nl ? (size_t)(nl - p) : strlen(p);

        /* Длинную строку не режем молча: обрезанная ссылка выглядела бы
           как настоящая, только с другим хвостом. Показываем маску. */
        char line[1024];
        char shown[1024];

        if (len >= sizeof(line)) {
            str_copy(shown, sizeof(shown), MASK_MARK);
        } else {
            memcpy(line, p, len);
            line[len] = '\0';
            if (line[0]) mask_link(str_trim(line), shown, sizeof(shown));
            else         shown[0] = '\0';
        }

        int n = snprintf(out + used, size - used, "%s\n", shown);
        if (n < 0 || (size_t)n >= size - used) break;
        used += (size_t)n;

        if (!nl) break;
        p = nl + 1;
    }
}
