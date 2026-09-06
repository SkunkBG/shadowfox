#ifndef SHADOWFOX_DNSCFG_H
#define SHADOWFOX_DNSCFG_H

/* Разбор running-config роутера в части DNS.

   Вышестоящие серверы записаны внутри секции dns-proxy строками вида
   «tls upstream 8.8.8.8 sni dns.google». Сами по себе такие строки ничем
   не отличаются от строк соседних секций: единственный признак
   принадлежности — отступ под заголовком секции.

   Отдельным файлом, чтобы проверка не тянула за собой половину демона. */

/* Заполняет out указателями внутрь text и возвращает их число.
   text изменяется: строки разрезаются на месте. */
int dns_upstreams(char *text, const char **out, int max);

#endif /* SHADOWFOX_DNSCFG_H */
