#include "routercfg.h"
#include "util.h"

#include <stdio.h>
#include <string.h>

/* Идём по секциям: заголовок стоит в первой колонке, содержимое с
   отступом. Поиск по началу строки не годится — серверы записаны
   внутри секции и начинаются со слова «tls» или «https». */
int dns_upstreams(char *text, const char **out, int max)
{
    int n = 0, inside = 0;

    for (char *line = strtok(text, "\n"); line && n < max;
         line = strtok(NULL, "\n")) {

        int indented = (line[0] == ' ' || line[0] == '\t');
        char *t = str_trim(line);
        if (!*t) continue;

        if (!indented) {
            inside = !strcmp(t, "dns-proxy");
            continue;
        }

        if (inside) {
            /* Внутри секции интересны только вышестоящие серверы. */
            if (strstr(t, "upstream")) out[n++] = t;
        } else if (!strncmp(t, "ip name-server ", 15)) {
            out[n++] = t;
        }
    }

    return n;
}

/* Интерфейсы, которые ещё берут DNS у провайдера.

   Признак «это внешнее подключение» — строка «ip dhcp client» внутри
   секции; признак «уже отключено» — «ip no name-servers». Отключать
   имеет смысл только первое без второго.

   Возвращает число найденных имён; они указывают внутрь text. */
int dns_isp_interfaces(char *text, const char **out, int max)
{
    int   n = 0;
    char *name = NULL;
    int   wan = 0, ignored = 0;

    for (char *line = strtok(text, "\n"); line; line = strtok(NULL, "\n")) {
        int   indented = (line[0] == ' ' || line[0] == '\t');
        char *t = str_trim(line);
        if (!*t) continue;

        if (!indented) {
            /* Секция кончилась — решаем по накопленному. */
            if (name && wan && !ignored && n < max) out[n++] = name;

            name = NULL; wan = 0; ignored = 0;

            if (!strncmp(t, "interface ", 10)) {
                name = t + 10;
                while (*name == ' ') name++;
                if (!*name) name = NULL;
            }
            continue;
        }

        if (!name) continue;

        if (!strncmp(t, "ip dhcp client", 14))    wan = 1;
        if (!strcmp(t, "ip no name-servers"))     ignored = 1;
    }

    if (name && wan && !ignored && n < max) out[n++] = name;
    return n;
}

/* Интерфейсы, между которыми выбирают политики доступа.

   В running-config они перечислены внутри секций «ip policy» строками
   «permit global Proxy1» и «no permit global ISP». Список router-
   специфичный, поэтому берём его у самого роутера, а не выдумываем. */
int policy_globals(char *text, const char **out, int max)
{
    int n = 0, inside = 0;

    for (char *line = strtok(text, "\n"); line; line = strtok(NULL, "\n")) {
        int   indented = (line[0] == ' ' || line[0] == '\t');
        char *t = str_trim(line);
        if (!*t) continue;

        if (!indented) {
            inside = !strncmp(t, "ip policy ", 10);
            continue;
        }
        if (!inside) continue;

        const char *p = t;
        if (!strncmp(p, "no ", 3)) p += 3;
        if (strncmp(p, "permit global ", 14) != 0) continue;

        p += 14;
        while (*p == ' ') p++;
        if (!*p) continue;

        int seen = 0;
        for (int i = 0; i < n; i++) if (!strcmp(out[i], p)) { seen = 1; break; }
        if (!seen && n < max) out[n++] = p;
    }

    return n;
}


int http_proxy_present(const char *text, const char *name)
{
    if (!text || !name || !name[0]) return 0;

    char head[96];
    int  n = snprintf(head, sizeof(head), "ip http proxy %s", name);
    if (n <= 0 || (size_t)n >= sizeof(head)) return 0;

    const char *line = text;
    for (;;) {
        /* Только заголовок секции, с начала строки: те же слова
           встречаются и во вложенных строках соседних секций. */
        if (!strncmp(line, head, (size_t)n)) {
            char after = line[n];
            if (after == '\0' || after == '\n' || after == '\r') return 1;
        }

        const char *nl = strchr(line, '\n');
        if (!nl) break;
        line = nl + 1;
    }

    return 0;
}
