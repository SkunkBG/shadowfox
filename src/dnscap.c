#include "dnscap.h"
#include "log.h"
#include "util.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define IP_PROTO_UDP 17
#define DNS_PORT     53

void dcap_init(dcap_t *c)
{
    memset(c, 0, sizeof(*c));
    c->fd = -1;
}

static unsigned rd16(const unsigned char *p)
{
    return (unsigned)p[0] << 8 | p[1];
}

int dcap_extract(const unsigned char *pkt, size_t len, dns_reply_t *out)
{
    if (!pkt || !out || len < 20) return -1;

    unsigned version = pkt[0] >> 4;
    size_t   off;

    if (version == 4) {
        size_t ihl = (size_t)(pkt[0] & 0x0F) * 4;
        if (ihl < 20 || ihl > len) return -1;
        if (pkt[9] != IP_PROTO_UDP) return -1;

        /* Фрагменты не собираем: DNS по UDP в них практически не
           встречается, а полусобранный пакет разбирать нельзя. */
        unsigned frag = rd16(pkt + 6);
        if (frag & 0x1FFF) return -1;

        off = ihl;
    } else if (version == 6) {
        if (len < 40) return -1;
        /* Заголовков расширения у DNS-ответов не бывает; если следующий
           заголовок не UDP, разбирать нечего. */
        if (pkt[6] != IP_PROTO_UDP) return -1;
        off = 40;
    } else {
        return -1;
    }

    if (off + 8 > len) return -1;

    unsigned sport = rd16(pkt + off);
    if (sport != DNS_PORT) return -1;

    unsigned ulen = rd16(pkt + off + 4);
    size_t   payload = off + 8;
    size_t   avail   = len - payload;

    /* Длина из заголовка UDP не должна выводить за пределы пакета. */
    if (ulen >= 8) {
        size_t claimed = (size_t)ulen - 8;
        if (claimed < avail) avail = claimed;
    }
    if (!avail) return -1;

    return dns_parse_reply(pkt + payload, avail, out);
}

#ifdef __linux__

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

/* Фильтр ядра: UDP с портом источника 53, IPv4 и IPv6, фрагменты
   отброшены. Байткод получен из `tcpdump -dd 'udp src port 53'`, но для
   типа канала RAW, а не Ethernet.

   Это важно и было исправлено после боевой проверки: у SOCK_DGRAM ядро
   не возвращает MAC-заголовок обратно перед фильтрацией — в packet_rcv
   он добавляется только для SOCK_RAW. Фильтр видит данные уже с
   сетевого уровня, и байткод для Ethernet читал тип протокола по
   смещению 12, попадая в середину IP-заголовка. Совпадений не было
   вовсе, при полностью живом сокете.

   Без фильтра в userspace копировался бы весь трафик моста: на роутере,
   через который проходят десятки гигабайт, это неприемлемо. */
static struct sock_filter DNS_FILTER[] = {
    { 0x30, 0, 0,  0x00000000 },   /* версия IP в первом байте */
    { 0x54, 0, 0,  0x000000f0 },
    { 0x15, 0, 4,  0x00000060 },   /* IPv6? */
    { 0x30, 0, 0,  0x00000006 },   /* следующий заголовок */
    { 0x15, 0, 13, 0x00000011 },   /* UDP */
    { 0x28, 0, 0,  0x00000028 },   /* порт источника */
    { 0x15, 10, 11, 0x00000035 },  /* 53 */
    { 0x30, 0, 0,  0x00000000 },   /* иначе IPv4? */
    { 0x54, 0, 0,  0x000000f0 },
    { 0x15, 0, 8,  0x00000040 },
    { 0x30, 0, 0,  0x00000009 },   /* протокол */
    { 0x15, 0, 6,  0x00000011 },   /* UDP */
    { 0x28, 0, 0,  0x00000006 },
    { 0x45, 4, 0,  0x00001fff },   /* не фрагмент */
    { 0xb1, 0, 0,  0x00000000 },   /* длина заголовка */
    { 0x48, 0, 0,  0x00000000 },   /* порт источника */
    { 0x15, 0, 1,  0x00000035 },   /* 53 */
    { 0x6,  0, 0,  0x0000ffff },
    { 0x6,  0, 0,  0x00000000 },
};

int dcap_open(dcap_t *c, const char *iface, char *err, unsigned err_size)
{
    if (!c) return -1;
    dcap_close(c);

    /* SOCK_DGRAM: ядро само снимает канальный заголовок, и до нас
       доходит уже IP-пакет. Фильтр видит те же данные, поэтому байткод
       выше рассчитан на сетевой уровень, а не на кадр Ethernet. */
    int fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL));
    if (fd < 0) {
        if (err) snprintf(err, err_size, "socket(AF_PACKET): %s", strerror(errno));
        return -1;
    }

    struct sock_fprog prog = {
        .len    = (unsigned short)(sizeof(DNS_FILTER) / sizeof(DNS_FILTER[0])),
        .filter = DNS_FILTER,
    };
    if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)) == 0) {
        c->filtered = 1;
    } else {
        /* Отказ фильтра — беда для нагрузки, но не для правильности:
           лишнее отсеется при разборе. Молчать об этом нельзя. */
        log_warn("фильтр DNS не принят ядром (%s), пакеты будут "
                 "отбираться в демоне", strerror(errno));
    }

    if (iface && *iface) {
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family   = AF_PACKET;
        sll.sll_protocol = htons(ETH_P_ALL);
        sll.sll_ifindex  = (int)if_nametoindex(iface);

        if (!sll.sll_ifindex) {
            if (err) snprintf(err, err_size, "нет интерфейса %s", iface);
            close(fd);
            return -1;
        }
        if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) != 0) {
            if (err) snprintf(err, err_size, "bind %s: %s", iface, strerror(errno));
            close(fd);
            return -1;
        }
        str_copy(c->iface, sizeof(c->iface), iface);
    }

    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    c->fd = fd;
    return 0;
}

#else  /* не Linux */

int dcap_open(dcap_t *c, const char *iface, char *err, unsigned err_size)
{
    (void)c; (void)iface;
    if (err && err_size)
        str_copy(err, err_size, "перехват DNS есть только в Linux");
    return -1;
}

#endif

void dcap_close(dcap_t *c)
{
    if (c && c->fd >= 0) {
        close(c->fd);
        c->fd = -1;
    }
}

int dcap_poll(dcap_t *c, void (*cb)(const dns_reply_t *, void *), void *ctx)
{
    if (!c || c->fd < 0) return 0;

    int handled = 0;

    /* Читаем всё, что накопилось, но не бесконечно: при шторме пакетов
       демон обязан вернуться в главный цикл и обработать сигналы. */
    for (int i = 0; i < 256; i++) {
        ssize_t n = read(c->fd, c->buf, sizeof(c->buf));
        if (n <= 0) break;

        c->seen++;

        dns_reply_t reply;
        if (dcap_extract(c->buf, (size_t)n, &reply) != 0) {
            c->ignored++;
            continue;
        }

        c->parsed++;
        handled++;
        if (cb) cb(&reply, ctx);
    }

    return handled;
}
