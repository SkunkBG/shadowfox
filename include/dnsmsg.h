#ifndef SHADOWFOX_DNSMSG_H
#define SHADOWFOX_DNSMSG_H

#include <stddef.h>

/* Разбор DNS-ответов.

   Сюда приходят байты прямо из сети, поэтому разбор обязан выдерживать
   любой мусор: обрезанные пакеты, ссылки за границу буфера, петли из
   указателей сжатия. Ни одно поле не читается без проверки границ. */

#define DNS_NAME_MAX     256
#define DNS_ANSWERS_MAX  32

typedef struct {
    char          name[DNS_NAME_MAX];  /* владелец записи */
    unsigned char addr[16];
    unsigned char family;              /* 4 или 6 */
    unsigned      ttl;
} dns_answer_t;

typedef struct {
    char         question[DNS_NAME_MAX];
    dns_answer_t answers[DNS_ANSWERS_MAX];
    int          answer_count;
    int          dropped;   /* адресов не поместилось */
} dns_reply_t;

/* Разбирает ответ. Возвращает 0, если это именно ответ и он цел,
   иначе -1. Запросы, ошибки и всё непонятное отбрасываются. */
int dns_parse_reply(const unsigned char *buf, size_t len, dns_reply_t *out);

#endif /* SHADOWFOX_DNSMSG_H */
