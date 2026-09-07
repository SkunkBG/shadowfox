#include "snicap.h"
#include "log.h"
#include "util.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define IP_PROTO_TCP 6
#define TLS_PORT     443

/* Типы записей и сообщений TLS. */
#define TLS_HANDSHAKE     0x16
#define TLS_CLIENT_HELLO  0x01
#define TLS_EXT_SERVER_NAME 0x0000
#define SNI_TYPE_HOST     0x00

void scap_init(scap_t *c)
{
    memset(c, 0, sizeof(*c));
    c->fd = -1;
}

static unsigned rd16(const unsigned char *p)
{
    return (unsigned)p[0] << 8 | p[1];
}

/* Имя приходит из сети и целиком подконтрольно клиенту, поэтому состав
   символов проверяем сами: дальше оно попадёт в сопоставление со
   списками и в журнал. Пропускаем только то, из чего вообще бывают
   доменные имена. */
static int name_ok(const char *s, size_t n)
{
    if (n == 0 || n > SCAP_NAME_MAX - 1) return 0;

    for (size_t i = 0; i < n; i++) {
        unsigned char ch = (unsigned char)s[i];
        int ok = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                 (ch >= '0' && ch <= '9') || ch == '-' || ch == '.' ||
                 ch == '_';
        if (!ok) return 0;
    }

    /* Точка по краям и две подряд — не имя, а мусор. */
    if (s[0] == '.' || s[n - 1] == '.') return 0;
    for (size_t i = 1; i < n; i++)
        if (s[i] == '.' && s[i - 1] == '.') return 0;

    return 1;
}

/* Разбор расширения server_name. off указывает на его содержимое,
   end — на конец доступных данных. */
static int parse_sni_ext(const unsigned char *p, size_t off, size_t ext_end,
                         sni_hit_t *out)
{
    /* server_name_list: длина списка, затем записи. */
    if (off + 2 > ext_end) return -2;
    size_t list_end = off + 2 + rd16(p + off);
    if (list_end > ext_end) return -2;
    off += 2;

    while (off + 3 <= list_end) {
        unsigned type = p[off];
        size_t   nlen = rd16(p + off + 1);
        off += 3;

        if (off + nlen > list_end) return -2;

        if (type == SNI_TYPE_HOST) {
            if (!name_ok((const char *)(p + off), nlen)) return -2;
            memcpy(out->name, p + off, nlen);
            out->name[nlen] = '\0';
            return 0;
        }
        off += nlen;
    }

    return -2;
}

int scap_extract(const unsigned char *pkt, size_t len, sni_hit_t *out)
{
    if (!pkt || !out || len < 40) return -1;

    memset(out, 0, sizeof(*out));

    unsigned version = pkt[0] >> 4;
    size_t   ip_hlen;

    if (version == 4) {
        ip_hlen = (size_t)(pkt[0] & 0x0f) * 4;
        if (ip_hlen < 20 || len < ip_hlen + 20) return -1;
        if (pkt[9] != IP_PROTO_TCP) return -1;

        /* Фрагмент: заголовка TCP в нём может не быть вовсе. */
        if ((rd16(pkt + 6) & 0x1fff) != 0) return -1;

        out->family = 4;
        memcpy(out->src, pkt + 12, 4);
        memcpy(out->dst, pkt + 16, 4);
    } else if (version == 6) {
        ip_hlen = 40;
        if (len < ip_hlen + 20) return -1;

        /* Заголовки расширений не разбираем: в TLS-соединении их не
           бывает, а гадать по цепочке — лишний код на горячем пути. */
        if (pkt[6] != IP_PROTO_TCP) return -1;

        out->family = 6;
        memcpy(out->src, pkt + 8,  16);
        memcpy(out->dst, pkt + 24, 16);
    } else {
        return -1;
    }

    const unsigned char *tcp = pkt + ip_hlen;
    size_t tcp_avail = len - ip_hlen;

    out->sport = rd16(tcp);
    out->dport = rd16(tcp + 2);
    if (out->dport != TLS_PORT) return -1;

    size_t tcp_hlen = (size_t)(tcp[12] >> 4) * 4;
    if (tcp_hlen < 20 || tcp_avail < tcp_hlen) return -1;

    const unsigned char *p = tcp + tcp_hlen;
    size_t avail = tcp_avail - tcp_hlen;

    /* Запись TLS: тип, версия, длина; затем сообщение handshake. */
    if (avail < 43) return -1;
    if (p[0] != TLS_HANDSHAKE) return -1;
    if (p[5] != TLS_CLIENT_HELLO) return -1;

    /* Дальше уже точно ClientHello, и всякий отказ — это разбор,
       который не сошёлся, а не чужой пакет. */
    size_t rec_end = 5 + (size_t)rd16(p + 3);
    size_t end     = rec_end < avail ? rec_end : avail;

    /* 5 запись + 4 handshake + 2 версия + 32 random. */
    size_t off = 43;

    if (off + 1 > end) return -2;
    off += 1 + p[off];                       /* session_id */

    if (off + 2 > end) return -2;
    off += 2 + rd16(p + off);                /* cipher_suites */

    if (off + 1 > end) return -2;
    off += 1 + p[off];                       /* compression_methods */

    if (off + 2 > end) return -2;
    size_t ext_end = off + 2 + rd16(p + off);
    if (ext_end > end) ext_end = end;        /* ClientHello мог не влезть
                                                в один сегмент */
    off += 2;

    while (off + 4 <= ext_end) {
        unsigned type = rd16(p + off);
        size_t   elen = rd16(p + off + 2);
        off += 4;

        if (off + elen > ext_end) return -2;

        if (type == TLS_EXT_SERVER_NAME)
            return parse_sni_ext(p, off, off + elen, out);

        off += elen;
    }

    return -2;
}

/* Фильтр ядра: TCP на порт назначения 443, где полезная нагрузка
   начинается с записи TLS handshake и сообщения ClientHello.

   Проверка нагрузки здесь принципиальна, а не для красоты. Отбор только
   по порту пропускал бы в userspace вообще весь исходящий HTTPS,
   включая каждую квитанцию при загрузке файла: на роутере это десятки
   тысяч копирований в секунду. С проверкой первого байта проходят
   только записи handshake, а их на соединение считаные штуки.

   Ветка IPv4 сверена с выводом
     tcpdump -y RAW -dd 'tcp dst port 443 and
        (tcp[((tcp[12] & 0xf0) >> 2)] = 0x16) and
        (tcp[((tcp[12] & 0xf0) >> 2) + 5] = 0x01)'
   Ветка IPv6 дописана руками: libpcap не умеет переменное смещение в
   ip6[], а у IPv6 заголовок фиксированный, и адресация проще. Обе ветки
   проверяются тестом check_snicap, который прогоняет этот же байткод
   через свой интерпретатор на собранных пакетах.

   Смещения считаются от сетевого уровня, а не от кадра Ethernet: у
   SOCK_DGRAM ядро не возвращает канальный заголовок перед фильтрацией.
   На этом здесь уже обжигались с фильтром DNS. */
static const scap_insn_t SNI_FILTER[] = {
    /* 0 */  { 0x30,  0,  0, 0x00000000 },  /* A = pkt[0] */
    /* 1 */  { 0x54,  0,  0, 0x000000f0 },  /* A &= 0xf0 — версия IP */
    /* 2 */  { 0x15, 17,  0, 0x00000060 },  /* IPv6 -> 20 */

    /* IPv4 */
    /* 3 */  { 0x15,  0, 30, 0x00000040 },  /* не IPv4 -> отказ */
    /* 4 */  { 0x30,  0,  0, 0x00000009 },  /* протокол */
    /* 5 */  { 0x15,  0, 28, 0x00000006 },  /* TCP? */
    /* 6 */  { 0x28,  0,  0, 0x00000006 },  /* флаги и смещение фрагмента */
    /* 7 */  { 0x45, 26,  0, 0x00001fff },  /* фрагмент -> отказ */
    /* 8 */  { 0xb1,  0,  0, 0x00000000 },  /* X = длина IP-заголовка */
    /* 9 */  { 0x48,  0,  0, 0x00000002 },  /* порт назначения */
    /* 10 */ { 0x15,  0, 23, 0x000001bb },  /* 443? */
    /* 11 */ { 0x50,  0,  0, 0x0000000c },  /* смещение данных TCP */
    /* 12 */ { 0x54,  0,  0, 0x000000f0 },
    /* 13 */ { 0x74,  0,  0, 0x00000002 },  /* A = длина заголовка TCP */
    /* 14 */ { 0x0c,  0,  0, 0x00000000 },  /* A += X */
    /* 15 */ { 0x07,  0,  0, 0x00000000 },  /* X = A — начало нагрузки */
    /* 16 */ { 0x50,  0,  0, 0x00000000 },
    /* 17 */ { 0x15,  0, 16, 0x00000016 },  /* запись handshake? */
    /* 18 */ { 0x50,  0,  0, 0x00000005 },
    /* 19 */ { 0x15, 13, 14, 0x00000001 },  /* ClientHello? */

    /* IPv6: заголовок фиксированный, 40 байт */
    /* 20 */ { 0x30,  0,  0, 0x00000006 },  /* следующий заголовок */
    /* 21 */ { 0x15,  0, 12, 0x00000006 },  /* TCP? */
    /* 22 */ { 0x28,  0,  0, 0x0000002a },  /* порт назначения, 40 + 2 */
    /* 23 */ { 0x15,  0, 10, 0x000001bb },  /* 443? */
    /* 24 */ { 0x30,  0,  0, 0x00000034 },  /* смещение данных, 40 + 12 */
    /* 25 */ { 0x54,  0,  0, 0x000000f0 },
    /* 26 */ { 0x74,  0,  0, 0x00000002 },
    /* 27 */ { 0x04,  0,  0, 0x00000028 },  /* A += 40 */
    /* 28 */ { 0x07,  0,  0, 0x00000000 },  /* X = начало нагрузки */
    /* 29 */ { 0x50,  0,  0, 0x00000000 },
    /* 30 */ { 0x15,  0,  3, 0x00000016 },  /* запись handshake? */
    /* 31 */ { 0x50,  0,  0, 0x00000005 },
    /* 32 */ { 0x15,  0,  1, 0x00000001 },  /* ClientHello? */

    /* 33 */ { 0x06,  0,  0, 0x0000ffff },  /* берём пакет */
    /* 34 */ { 0x06,  0,  0, 0x00000000 },  /* отказ */
};


const scap_insn_t *scap_filter(unsigned *count)
{
    if (count) *count = (unsigned)(sizeof(SNI_FILTER) / sizeof(SNI_FILTER[0]));
    return SNI_FILTER;
}

#ifdef __linux__

#include <fcntl.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <sys/socket.h>

int scap_open(scap_t *c, const char *iface, char *err, unsigned err_size)
{
    if (!c) return -1;
    scap_close(c);

    int fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL));
    if (fd < 0) {
        if (err) snprintf(err, err_size, "socket(AF_PACKET): %s", strerror(errno));
        return -1;
    }

    /* Раскладки обязаны совпадать: массив объявлен своим типом, чтобы
       жить в переносимой части и проверяться тестом. */
    _Static_assert(sizeof(scap_insn_t) == sizeof(struct sock_filter),
                   "scap_insn_t разошёлся со struct sock_filter");

    unsigned fcount = 0;
    const scap_insn_t *farr = scap_filter(&fcount);

    struct sock_fprog prog = {
        .len    = (unsigned short)fcount,
        .filter = (struct sock_filter *)(void *)(uintptr_t)farr,
    };
    if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)) == 0) {
        c->filtered = 1;
    } else {
        /* Здесь отказ фильтра хуже, чем у DNS: без него в userspace
           поедет весь HTTPS моста. Разбор всё отсеет, но нагрузка того
           не стоит — работаем без перехвата SNI. */
        if (err)
            snprintf(err, err_size, "фильтр TLS не принят ядром: %s",
                     strerror(errno));
        close(fd);
        return -1;
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

    fcntl(fd, F_SETFD, FD_CLOEXEC);

    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    c->fd = fd;
    return 0;
}

#else  /* не Linux */

int scap_open(scap_t *c, const char *iface, char *err, unsigned err_size)
{
    (void)c; (void)iface;
    if (err && err_size)
        str_copy(err, err_size, "перехват TLS есть только в Linux");
    return -1;
}

#endif

void scap_close(scap_t *c)
{
    if (!c) return;
    if (c->fd >= 0) close(c->fd);
    c->fd       = -1;
    c->filtered = 0;
}

int scap_poll(scap_t *c, void (*cb)(const sni_hit_t *, void *), void *ctx)
{
    if (!c || c->fd < 0) return 0;

    int handled = 0;

    /* Читаем всё, что накопилось, но не бесконечно: при шторме пакетов
       демон обязан вернуться в главный цикл и обработать сигналы. */
    for (int i = 0; i < 256; i++) {
        ssize_t n = read(c->fd, c->buf, sizeof(c->buf));
        if (n <= 0) break;

        c->seen++;

        sni_hit_t hit;
        int       why = scap_extract(c->buf, (size_t)n, &hit);

        if (why != 0) {
            if (why == -1) {
                c->drop_nottls++;
            } else {
                c->drop_bad++;
                log_debug("ClientHello не разобран, %zd байт", n);
            }
            continue;
        }

        c->parsed++;
        handled++;
        if (cb) cb(&hit, ctx);
    }

    return handled;
}
