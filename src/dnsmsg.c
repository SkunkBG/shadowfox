#include "dnsmsg.h"

#include <string.h>

#define DNS_HEADER_LEN   12
#define DNS_TYPE_A       1
#define DNS_TYPE_CNAME   5
#define DNS_TYPE_AAAA    28
#define DNS_CLASS_IN     1

/* Ограничение на прыжки по указателям сжатия. Без него подделанный
   пакет с петлёй заставил бы разбор крутиться вечно. */
#define DNS_MAX_JUMPS    16

static unsigned rd16(const unsigned char *p) { return (unsigned)p[0] << 8 | p[1]; }
static unsigned rd32(const unsigned char *p)
{
    return (unsigned)p[0] << 24 | (unsigned)p[1] << 16 |
           (unsigned)p[2] << 8  | (unsigned)p[3];
}

/* Читает имя начиная с off. Кладёт его в out в виде "a.b.c".
   В *after возвращает смещение сразу за именем в исходном потоке —
   для сжатых имён это позиция после указателя, а не после цели.
   Возвращает 0 при успехе. */
static int read_name(const unsigned char *buf, size_t len, size_t off,
                     char *out, size_t out_size, size_t *after)
{
    size_t o        = off;
    size_t written  = 0;
    int    jumps    = 0;
    int    jumped   = 0;

    if (out_size) out[0] = '\0';

    for (;;) {
        if (o >= len) return -1;

        unsigned char label = buf[o];

        if ((label & 0xC0) == 0xC0) {
            /* Указатель сжатия: два байта, младшие 14 бит — смещение. */
            if (o + 1 >= len) return -1;
            size_t target = ((size_t)(label & 0x3F) << 8) | buf[o + 1];

            if (!jumped) {
                if (after) *after = o + 2;
                jumped = 1;
            }
            if (++jumps > DNS_MAX_JUMPS) return -1;
            /* Прыжок только назад: вперёд — верный признак петли. */
            if (target >= o) return -1;

            o = target;
            continue;
        }

        if (label & 0xC0) return -1;    /* зарезервированные биты */

        if (label == 0) {
            if (!jumped && after) *after = o + 1;
            break;
        }

        o++;
        if (o + label > len) return -1;

        if (written) {
            if (written + 1 >= out_size) return -1;
            out[written++] = '.';
        }
        if (written + label >= out_size) return -1;

        for (unsigned i = 0; i < label; i++) {
            unsigned char c = buf[o + i];
            /* Приводим к нижнему регистру сразу: сравнивать со списком
               доменов всё равно без учёта регистра. */
            if (c >= 'A' && c <= 'Z') c = (unsigned char)(c - 'A' + 'a');
            out[written++] = (char)c;
        }
        out[written] = '\0';
        o += label;
    }

    if (written == 0 && out_size) out[0] = '\0';
    return 0;
}

int dns_parse_reply(const unsigned char *buf, size_t len, dns_reply_t *out)
{
    if (!buf || !out || len < DNS_HEADER_LEN) return -1;

    memset(out, 0, sizeof(*out));

    unsigned flags = rd16(buf + 2);

    /* Нас интересуют только ответы без ошибки. Запросы и отказы
       адресов не несут. */
    if (!(flags & 0x8000)) return -1;          /* QR: это запрос */
    if ((flags & 0x000F) != 0) return -1;      /* RCODE не NOERROR */

    unsigned qdcount = rd16(buf + 4);
    unsigned ancount = rd16(buf + 6);

    if (qdcount != 1) return -1;               /* иных не бывает на практике */
    if (ancount == 0) return -1;

    size_t off = DNS_HEADER_LEN;

    if (read_name(buf, len, off, out->question, sizeof(out->question), &off) != 0)
        return -1;

    if (off + 4 > len) return -1;
    off += 4;                                   /* QTYPE и QCLASS */

    for (unsigned i = 0; i < ancount; i++) {
        char name[DNS_NAME_MAX];
        if (read_name(buf, len, off, name, sizeof(name), &off) != 0) return -1;

        if (off + 10 > len) return -1;
        unsigned type   = rd16(buf + off);
        unsigned class_ = rd16(buf + off + 2);
        unsigned ttl    = rd32(buf + off + 4);
        unsigned rdlen  = rd16(buf + off + 8);
        off += 10;

        if (off + rdlen > len) return -1;

        if (class_ == DNS_CLASS_IN &&
            ((type == DNS_TYPE_A    && rdlen == 4) ||
             (type == DNS_TYPE_AAAA && rdlen == 16))) {

            if (out->answer_count >= DNS_ANSWERS_MAX) {
                out->dropped++;
            } else {
                dns_answer_t *a = &out->answers[out->answer_count++];
                memcpy(a->name, name, sizeof(a->name));
                memcpy(a->addr, buf + off, rdlen);
                a->family = (type == DNS_TYPE_A) ? 4 : 6;
                a->ttl    = ttl;
            }
        }
        /* CNAME пропускаем как запись, но имя из него всё равно уже
           учтено: владелец следующих записей — цель псевдонима, и она
           попадёт в name на следующем витке. */

        off += rdlen;
    }

    return out->answer_count ? 0 : -1;
}
