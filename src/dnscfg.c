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
