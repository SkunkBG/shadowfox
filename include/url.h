#ifndef SHADOWFOX_URL_H
#define SHADOWFOX_URL_H

#include <stddef.h>

#define URL_SCHEME_MAX 16
#define URL_USER_MAX   128
#define URL_HOST_MAX   256
#define URL_PATH_MAX   256
#define URL_QUERY_MAX  1024
#define URL_FRAG_MAX   256

typedef struct {
    char scheme[URL_SCHEME_MAX];
    char user[URL_USER_MAX];     /* до '@', уже декодировано */
    char host[URL_HOST_MAX];     /* без скобок у IPv6 */
    int  port;                   /* 0, если не указан */
    int  host_is_ipv6;
    char path[URL_PATH_MAX];     /* как есть, не декодировано */
    char query[URL_QUERY_MAX];   /* как есть, не декодировано */
    char fragment[URL_FRAG_MAX]; /* уже декодировано */
} url_t;

/* Разбирает scheme://user@host:port/path?query#fragment.
   Возвращает 0 при успехе, -1 если это не похоже на ссылку. */
int url_parse(const char *s, url_t *u);

/* Percent-декодирование. '+' остаётся плюсом: это URL, а не тело формы,
   и в share-ссылках плюс встречается внутри значений как есть.
   Возвращает 0, либо -1 при переполнении буфера. */
int url_pct_decode(const char *in, char *out, size_t out_size);

/* Ищет параметр в query. Возвращает 1 и кладёт декодированное значение
   в out, 0 если параметра нет, -1 при переполнении. */
int url_query_get(const url_t *u, const char *key, char *out, size_t out_size);

#endif /* SHADOWFOX_URL_H */
