#include "dnscap.h"
#include "log.h"
#include "util.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
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
    return dcap_extract_why(pkt, len, out) == 0 ? 0 : -1;
}

/* Запоминаем, кому пришёл DNS-ответ. Годится любой разбираемый ответ,
   включая NXDOMAIN и пустой AAAA: он всё равно доказывает, что
   устройство спрашивает роутер, а это и есть предмет проверки. */
static void note_client(dcap_t *c, const unsigned char *pkt, size_t len, long now)
{
    unsigned char addr[16];
    unsigned      family;

    if (len < 20) return;

    if ((pkt[0] >> 4) == 4) {
        memcpy(addr, pkt + 16, 4);
        memset(addr + 4, 0, 12);
        family = 4;
    } else if ((pkt[0] >> 4) == 6) {
        if (len < 40) return;
        memcpy(addr, pkt + 24, 16);
        family = 6;
    } else {
        return;
    }

    int len_cmp = (family == 4) ? 4 : 16;

    for (int i = 0; i < c->client_count; i++) {
        if (c->clients[i].family != family) continue;
        if (memcmp(c->clients[i].addr, addr, (size_t)len_cmp) != 0) continue;
        c->clients[i].last = now;
        return;
    }

    int slot = c->client_count;
    if (slot >= DCAP_CLIENTS_MAX) {
        /* Вытесняем самое давнее: список устройств не должен расти
           бесконечно из-за случайных гостей сети. */
        slot = 0;
        for (int i = 1; i < c->client_count; i++)
            if (c->clients[i].last < c->clients[slot].last) slot = i;
    } else {
        c->client_count++;
    }

    memcpy(c->clients[slot].addr, addr, sizeof(addr));
    c->clients[slot].family = (unsigned char)family;
    c->clients[slot].last   = now;
}

int dcap_seen_client(const dcap_t *c, int family, const unsigned char *addr,
                     long now, int window)
{
    if (!c || !addr || (family != 4 && family != 6)) return 0;

    size_t n = (family == 4) ? 4 : 16;

    for (int i = 0; i < c->client_count; i++) {
        if (c->clients[i].family != family) continue;
        if (memcmp(c->clients[i].addr, addr, n) != 0) continue;
        return (now - c->clients[i].last) <= window;
    }

    return 0;
}

int dcap_client_count(const dcap_t *c, long now, int window)
{
    if (!c) return 0;

    int n = 0;
    for (int i = 0; i < c->client_count; i++)
        if (now - c->clients[i].last <= window) n++;

    return n;
}

int dcap_extract_why(const unsigned char *pkt, size_t len, dns_reply_t *out)
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

    int rc = dns_parse_reply(pkt + payload, avail, out);
    return rc == 0 ? 0 : (rc == -2 ? -2 : -3);
}

/* Чтение пакета вместе с его направлением. Без направления перехват
   верил любому пакету с портом источника 53: устройство в сети слало
   поддельный «ответ» на MAC роутера, и адрес из него заворачивался в
   туннель для всех. Ответ роутера — и только он — приходит как
   PACKET_OUTGOING: это направление ядро ставит само, подделать его
   с другого хоста нельзя. */
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

static ssize_t cap_read(int fd, void *buf, size_t n, int *pkttype)
{
    struct sockaddr_ll from;
    socklen_t          flen = sizeof(from);
    memset(&from, 0, sizeof(from));

    ssize_t got = recvfrom(fd, buf, n, 0, (struct sockaddr *)&from, &flen);
    if (got > 0 && pkttype) *pkttype = from.sll_pkttype;
    return got;
}

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

    /* Тот же случай, что и с веб-сокетом: чужим процессам он не нужен. */
    fcntl(fd, F_SETFD, FD_CLOEXEC);

    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    c->fd = fd;
    c->watching_since = (long)time(NULL);
    return 0;
}

#else  /* не Linux */

static ssize_t cap_read(int fd, void *buf, size_t n, int *pkttype)
{
    if (pkttype) *pkttype = -1;
    return read(fd, buf, n);
}

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
        int     pkttype = -1;
        ssize_t n = cap_read(c->fd, c->buf, sizeof(c->buf), &pkttype);
        if (n <= 0) break;

        c->seen++;

#ifdef __linux__
        if (pkttype >= 0 && pkttype != PACKET_OUTGOING) {
            c->ignored++;
            c->drop_foreign++;
            continue;
        }
#endif

        dns_reply_t reply;
        int         why = dcap_extract_why(c->buf, (size_t)n, &reply);

        /* -1 значит «не наш пакет»: там и адресата брать неоткуда. */
        if (why != -1) note_client(c, c->buf, (size_t)n, (long)time(NULL));

        if (why != 0) {
            c->ignored++;
            if (why == -1)      c->drop_notip++;
            else if (why == -2) c->drop_empty++;
            else                c->drop_bad++;

            /* Первые байты показывают версию IP и протокол — по ним
               сразу видно, тот ли слой отдаёт сокет. */
            log_debug("пакет мимо (%s), %zd байт, начало %02x %02x %02x %02x",
                      why == -1 ? "не UDP/53"
                                : (why == -2 ? "без адресов" : "битый"),
                      n, c->buf[0], c->buf[1],
                      n > 2 ? c->buf[2] : 0, n > 3 ? c->buf[3] : 0);
            continue;
        }

        c->parsed++;
        handled++;
        if (cb) cb(&reply, ctx);
    }

    return handled;
}
