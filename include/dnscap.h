#ifndef SHADOWFOX_DNSCAP_H
#define SHADOWFOX_DNSCAP_H

#include "dnsmsg.h"

#include <stddef.h>

/* Пассивный перехват DNS-ответов.

   Мы не встраиваемся в цепочку резолвинга: слушаем сеть со стороны и
   читаем ответы, которые и так летят к клиентам. Если демон упадёт,
   DNS у всей сети продолжит работать — в отличие от схемы с
   DNS-прокси, где резолвер становится точкой отказа. */

#define DCAP_IFACE_MAX 32
#define DCAP_BUF_BYTES 2048

typedef struct {
    int           fd;
    char          iface[DCAP_IFACE_MAX];
    int           filtered;        /* фильтр ядра принят */
    unsigned long seen;            /* пакетов прочитано */
    unsigned long parsed;          /* ответов разобрано */
    unsigned long ignored;         /* всего отброшено */

    /* Раздельные причины отказа. Общий счётчик «мимо» сваливает в кучу
       не тот протокол, не ответ и ответ без адресов — а лечатся они
       по-разному. */
    unsigned long drop_notip;      /* не IPv4/IPv6, не UDP, не порт 53 */
    unsigned long drop_notreply;   /* не ответ, ошибка либо без адресов */
    unsigned char buf[DCAP_BUF_BYTES];
} dcap_t;

void dcap_init(dcap_t *c);

/* Открывает сокет захвата на интерфейсе. Пустое имя — все интерфейсы.
   Возвращает 0 при успехе. Только Linux; в остальных системах вернёт
   -1 с внятной причиной. */
int  dcap_open(dcap_t *c, const char *iface, char *err, unsigned err_size);
void dcap_close(dcap_t *c);

/* Разбирает IP-пакет: IPv4 или IPv6, UDP, порт источника 53, и дальше
   само DNS-сообщение. Возвращает 0, если это оказался DNS-ответ.

   Вынесено отдельно от сокета намеренно: разбор проверяется тестами на
   любой машине, а сокет живёт только на Linux. */
int  dcap_extract(const unsigned char *pkt, size_t len, dns_reply_t *out);

/* То же, но с указанием, на чём именно отказано: 0 — успех,
   -1 — не похоже на UDP-ответ с порта 53, -2 — DNS-сообщение
   не разобралось или в нём нет адресов. */
int  dcap_extract_why(const unsigned char *pkt, size_t len, dns_reply_t *out);

/* Читает готовые пакеты и вызывает cb на каждый разобранный ответ.
   Возвращает число разобранных ответов. */
int  dcap_poll(dcap_t *c, void (*cb)(const dns_reply_t *, void *), void *ctx);

#endif /* SHADOWFOX_DNSCAP_H */
