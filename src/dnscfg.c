#include "dnscfg.h"
#include "util.h"

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

