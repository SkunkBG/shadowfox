#include "snicap.h"
#include "log.h"
#include "util.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
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

/* Заголовки IP и TCP: 5-tuple, номер последовательности и нагрузка.
   -1 — не наш пакет (не TCP, не 443, фрагмент). */
typedef struct {
    unsigned char        family;
    unsigned char        src[16], dst[16];
    unsigned             sport, dport;
    unsigned             seq;
    const unsigned char *payload;
    size_t               plen;
} tcp_view_t;

static int tcp_view(const unsigned char *pkt, size_t len, tcp_view_t *v)
{
    if (!pkt || !v || len < 40) return -1;
    memset(v, 0, sizeof(*v));

    unsigned version = pkt[0] >> 4;
    size_t   ip_hlen;

    if (version == 4) {
        ip_hlen = (size_t)(pkt[0] & 0x0f) * 4;
        if (ip_hlen < 20 || len < ip_hlen + 20) return -1;
        if (pkt[9] != IP_PROTO_TCP) return -1;

        /* Фрагмент: заголовка TCP в нём может не быть вовсе. */
        if ((rd16(pkt + 6) & 0x1fff) != 0) return -1;

        v->family = 4;
        memcpy(v->src, pkt + 12, 4);
        memcpy(v->dst, pkt + 16, 4);
    } else if (version == 6) {
        ip_hlen = 40;
        if (len < ip_hlen + 20) return -1;

        /* Заголовки расширений не разбираем: в TLS-соединении их не
           бывает, а гадать по цепочке — лишний код на горячем пути. */
        if (pkt[6] != IP_PROTO_TCP) return -1;

        v->family = 6;
        memcpy(v->src, pkt + 8,  16);
        memcpy(v->dst, pkt + 24, 16);
    } else {
        return -1;
    }

    const unsigned char *tcp = pkt + ip_hlen;
    size_t tcp_avail = len - ip_hlen;

    v->sport = rd16(tcp);
    v->dport = rd16(tcp + 2);
    if (v->dport != TLS_PORT) return -1;

    v->seq = (unsigned)tcp[4] << 24 | (unsigned)tcp[5] << 16 |
             (unsigned)tcp[6] << 8  | (unsigned)tcp[7];

    size_t tcp_hlen = (size_t)(tcp[12] >> 4) * 4;
    if (tcp_hlen < 20 || tcp_avail < tcp_hlen) return -1;

    v->payload = tcp + tcp_hlen;
    v->plen    = tcp_avail - tcp_hlen;
    return 0;
}

/* Разбор ClientHello из нагрузки TLS. 0 — имя найдено; -1 — это не
   ClientHello; -2 — похоже, но не сошлось; -3 — данные кончились раньше
   конца записи, продолжение в следующем сегменте. */
static int tls_client_hello(const unsigned char *p, size_t avail, sni_hit_t *out)
{
    /* Запись TLS: тип, версия, длина; затем сообщение handshake. */
    if (avail < 6) return -1;
    if (p[0] != TLS_HANDSHAKE) return -1;
    if (p[5] != TLS_CLIENT_HELLO) return -1;

    size_t rec_end = 5 + (size_t)rd16(p + 3);
    int    more    = rec_end > avail;   /* запись длиннее того, что есть */
    size_t end     = more ? avail : rec_end;

    /* Дальше уже точно ClientHello. Нехватка данных внутри записи —
       это -3, а не -2: продолжение ещё может прийти. */
#define NEED(n) do { if (off + (n) > end) return more ? -3 : -2; } while (0)

    /* 5 запись + 4 handshake + 2 версия + 32 random. */
    size_t off = 43;
    NEED(1);  off += 1 + p[off];                       /* session_id */
    NEED(2);  off += 2 + rd16(p + off);                /* cipher_suites */
    NEED(1);  off += 1 + p[off];                       /* compression_methods */
    NEED(2);
    size_t ext_end = off + 2 + rd16(p + off);
    off += 2;
    if (ext_end > rec_end) return -2;                  /* врёт про длину */

    while (off + 4 <= ext_end) {
        if (off + 4 > end) return more ? -3 : -2;
        unsigned type = rd16(p + off);
        size_t   elen = rd16(p + off + 2);
        off += 4;

        if (off + elen > ext_end) return -2;
        if (off + elen > end)      return more ? -3 : -2;

        if (type == TLS_EXT_SERVER_NAME)
            return parse_sni_ext(p, off, off + elen, out);

        off += elen;
    }
#undef NEED

    /* Расширения кончились, а имени нет: если запись обрывается — оно
       может быть дальше, иначе его нет вовсе. */
    return (more && off < ext_end) ? -3 : -2;
}

int scap_extract(const unsigned char *pkt, size_t len, sni_hit_t *out)
{
    if (!pkt || !out) return -1;
    memset(out, 0, sizeof(*out));

    tcp_view_t v;
    if (tcp_view(pkt, len, &v) != 0) return -1;

    out->family = v.family;
    memcpy(out->src, v.src, 16);
    memcpy(out->dst, v.dst, 16);
    out->sport = v.sport;
    out->dport = v.dport;

    return tls_client_hello(v.payload, v.plen, out);
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
   На этом здесь уже обжигались с фильтром DNS.

   Кроме ClientHello фильтр пропускает короткие сегменты с первым байтом
   не 0x17 — это продолжения приветствия, не поместившегося в один
   сегмент. Данные приложения после рукопожатия — всегда записи 0x17;
   произвольным байтом начинаются только хвосты больших записей, и
   ограничение в 640 байт отсекает почти все из них. Остаток отсеивает
   демон одним сравнением номера последовательности. */
static const scap_insn_t SNI_FILTER[] = {
    /* 0 */  { 0x30,  0,  0, 0x00000000 },  /* A = pkt[0] */
    /* 1 */  { 0x54,  0,  0, 0x000000f0 },  /* A &= 0xf0 — версия IP */
    /* 2 */  { 0x15, 22,  0, 0x00000060 },  /* IPv6 -> 25 */

    /* IPv4 */
    /* 3 */  { 0x15,  0, 41, 0x00000040 },  /* не IPv4 -> отказ */
    /* 4 */  { 0x30,  0,  0, 0x00000009 },  /* протокол */
    /* 5 */  { 0x15,  0, 39, 0x00000006 },  /* TCP? */
    /* 6 */  { 0x28,  0,  0, 0x00000006 },  /* флаги и смещение фрагмента */
    /* 7 */  { 0x45, 37,  0, 0x00001fff },  /* фрагмент -> отказ */
    /* 8 */  { 0xb1,  0,  0, 0x00000000 },  /* X = длина IP-заголовка */
    /* 9 */  { 0x48,  0,  0, 0x00000002 },  /* порт назначения */
    /* 10 */ { 0x15,  0, 34, 0x000001bb },  /* 443? */
    /* 11 */ { 0x50,  0,  0, 0x0000000c },  /* смещение данных TCP */
    /* 12 */ { 0x54,  0,  0, 0x000000f0 },
    /* 13 */ { 0x74,  0,  0, 0x00000002 },  /* A = длина заголовка TCP */
    /* 14 */ { 0x0c,  0,  0, 0x00000000 },  /* A += X */
    /* 15 */ { 0x07,  0,  0, 0x00000000 },  /* X = A — начало нагрузки */
    /* 16 */ { 0x50,  0,  0, 0x00000000 },  /* первый байт нагрузки */
    /* 17 */ { 0x15,  0,  2, 0x00000016 },  /* не handshake -> 20 */
    /* 18 */ { 0x50,  0,  0, 0x00000005 },
    /* 19 */ { 0x15, 24, 25, 0x00000001 },  /* ClientHello? берём : отказ */
    /* 20 */ { 0x15, 24,  0, 0x00000017 },  /* данные приложения -> отказ */
    /* 21 */ { 0x28,  0,  0, 0x00000002 },  /* полная длина IP */
    /* 22 */ { 0x1c,  0,  0, 0x00000000 },  /* A -= X: длина нагрузки */
    /* 23 */ { 0x25, 21,  0, 0x00000280 },  /* длиннее 640 -> отказ */
    /* 24 */ { 0x15, 20, 19, 0x00000000 },  /* пустая -> отказ, иначе берём */

    /* IPv6: заголовок фиксированный, 40 байт */
    /* 25 */ { 0x30,  0,  0, 0x00000006 },  /* следующий заголовок */
    /* 26 */ { 0x15,  0, 18, 0x00000006 },  /* TCP? */
    /* 27 */ { 0x28,  0,  0, 0x0000002a },  /* порт назначения, 40 + 2 */
    /* 28 */ { 0x15,  0, 16, 0x000001bb },  /* 443? */
    /* 29 */ { 0x30,  0,  0, 0x00000034 },  /* смещение данных, 40 + 12 */
    /* 30 */ { 0x54,  0,  0, 0x000000f0 },
    /* 31 */ { 0x74,  0,  0, 0x00000002 },
    /* 32 */ { 0x04,  0,  0, 0x00000028 },  /* A += 40 */
    /* 33 */ { 0x07,  0,  0, 0x00000000 },  /* X = начало нагрузки */
    /* 34 */ { 0x50,  0,  0, 0x00000000 },
    /* 35 */ { 0x15,  0,  2, 0x00000016 },  /* не handshake -> 38 */
    /* 36 */ { 0x50,  0,  0, 0x00000005 },
    /* 37 */ { 0x15,  6,  7, 0x00000001 },  /* ClientHello? берём : отказ */
    /* 38 */ { 0x15,  6,  0, 0x00000017 },  /* данные приложения -> отказ */
    /* 39 */ { 0x28,  0,  0, 0x00000004 },  /* длина нагрузки IPv6 */
    /* 40 */ { 0x04,  0,  0, 0x00000028 },  /* + 40 */
    /* 41 */ { 0x1c,  0,  0, 0x00000000 },  /* - X: длина нагрузки TCP */
    /* 42 */ { 0x25,  2,  0, 0x00000280 },  /* длиннее 640 -> отказ */
    /* 43 */ { 0x15,  1,  0, 0x00000000 },  /* пустая -> отказ */

    /* 44 */ { 0x06,  0,  0, 0x0000ffff },  /* берём пакет */
    /* 45 */ { 0x06,  0,  0, 0x00000000 },  /* отказ */
};


const scap_insn_t *scap_filter(unsigned *count)
{
    if (count) *count = (unsigned)(sizeof(SNI_FILTER) / sizeof(SNI_FILTER[0]));
    return SNI_FILTER;
}

#ifdef __linux__

/* htons: у dnscap.c он приезжает попутно через <sys/ioctl.h>, но
   полагаться на это нельзя — включаем явно. */
#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <sys/socket.h>

/* Пакет вместе с направлением. Нам нужны только те, что клиент шлёт
   роутеру (PACKET_HOST): проходящее мостом между двумя хостами сети и
   широковещательное — не наш трафик, а подделку с чужим адресом
   источника это, увы, не отсекает — она тоже адресована роутеру. От
   неё защищает бюджет обрывов в движке. */
static ssize_t cap_read(int fd, void *buf, size_t n, int *pkttype)
{
    struct sockaddr_ll from;
    socklen_t          flen = sizeof(from);
    memset(&from, 0, sizeof(from));

    ssize_t got = recvfrom(fd, buf, n, 0, (struct sockaddr *)&from, &flen);
    if (got > 0 && pkttype) *pkttype = from.sll_pkttype;
    return got;
}

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

static ssize_t cap_read(int fd, void *buf, size_t n, int *pkttype)
{
    if (pkttype) *pkttype = -1;
    return read(fd, buf, n);
}

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

static int same_flow(const tcp_view_t *v, unsigned char family,
                     const unsigned char *src, const unsigned char *dst,
                     unsigned sport, unsigned dport)
{
    size_t alen = family == 4 ? 4 : 16;
    return v->family == family && v->sport == sport && v->dport == dport &&
           memcmp(v->src, src, alen) == 0 && memcmp(v->dst, dst, alen) == 0;
}

static void fill_hit(sni_hit_t *h, const tcp_view_t *v)
{
    h->family = v->family;
    memcpy(h->src, v->src, 16);
    memcpy(h->dst, v->dst, 16);
    h->sport = v->sport;
    h->dport = v->dport;
}

int scap_handle(scap_t *c, const unsigned char *pkt, size_t len, int pkttype,
                long now, void (*cb)(const sni_hit_t *, void *), void *ctx)
{
    if (!c || !pkt) return 0;

    c->seen++;

#ifdef __linux__
    if (pkttype >= 0 && pkttype != PACKET_HOST) {
        c->drop_foreign++;
        return 0;
    }
#else
    (void)pkttype;
#endif

    /* Старые склейки сгорают: продолжение, которое не пришло за две
       секунды, уже не придёт. */
    for (int i = 0; i < SCAP_PARTIAL_MAX; i++) {
        if (c->partial[i].len && now - c->partial[i].at > SCAP_PARTIAL_TTL) {
            c->partial[i].len = 0;
            c->partial_lost++;
        }
    }

    tcp_view_t v;
    if (tcp_view(pkt, len, &v) != 0 || v.plen == 0) {
        c->drop_nottls++;
        return 0;
    }

    sni_hit_t hit;
    memset(&hit, 0, sizeof(hit));
    fill_hit(&hit, &v);

    /* Продолжение ожидающего приветствия? Сверяем поток и номер
       последовательности: чужой сегмент к нам не приклеится. */
    for (int i = 0; i < SCAP_PARTIAL_MAX; i++) {
        if (!c->partial[i].len) continue;
        if (!same_flow(&v, c->partial[i].family, c->partial[i].src,
                       c->partial[i].dst, c->partial[i].sport, c->partial[i].dport))
            continue;
        if (v.seq != c->partial[i].next_seq) continue;

        if (c->partial[i].len + v.plen > SCAP_PARTIAL_BYTES) {
            c->partial[i].len = 0;
            c->partial_lost++;
            c->drop_bad++;
            return 0;
        }
        memcpy(c->partial[i].data + c->partial[i].len, v.payload, v.plen);
        c->partial[i].len      += v.plen;
        c->partial[i].next_seq += (unsigned)v.plen;
        c->partial[i].at        = now;

        int r = tls_client_hello(c->partial[i].data, c->partial[i].len, &hit);
        if (r == -3) return 0;                 /* ждём ещё */

        c->partial[i].len = 0;
        if (r != 0) { c->partial_lost++; c->drop_bad++; return 0; }

        c->reassembled++;
        c->parsed++;
        if (cb) cb(&hit, ctx);
        return 1;
    }

    int r = tls_client_hello(v.payload, v.plen, &hit);

    if (r == -1) { c->drop_nottls++; return 0; }

    if (r == -3) {
        /* Приветствие обрывается на границе сегмента — откладываем хвост
           и ждём продолжение. Свободный либо самый старый слот. */
        if (v.plen > SCAP_PARTIAL_BYTES) { c->drop_bad++; return 0; }

        int slot = 0;
        for (int i = 0; i < SCAP_PARTIAL_MAX; i++) {
            if (!c->partial[i].len) { slot = i; break; }
            if (c->partial[i].at < c->partial[slot].at) slot = i;
        }
        if (c->partial[slot].len) c->partial_lost++;

        c->partial[slot].family = v.family;
        memcpy(c->partial[slot].src, v.src, 16);
        memcpy(c->partial[slot].dst, v.dst, 16);
        c->partial[slot].sport    = v.sport;
        c->partial[slot].dport    = v.dport;
        c->partial[slot].next_seq = v.seq + (unsigned)v.plen;
        c->partial[slot].len      = v.plen;
        c->partial[slot].at       = now;
        memcpy(c->partial[slot].data, v.payload, v.plen);
        c->partial_kept++;
        return 0;
    }

    if (r != 0) {
        c->drop_bad++;
        log_debug("ClientHello не разобран, %zu байт", len);
        return 0;
    }

    c->parsed++;
    if (cb) cb(&hit, ctx);
    return 1;
}

int scap_poll(scap_t *c, void (*cb)(const sni_hit_t *, void *), void *ctx)
{
    if (!c || c->fd < 0) return 0;

    int  handled = 0;
    long now     = (long)time(NULL);

    /* Читаем всё, что накопилось, но не бесконечно: при шторме пакетов
       демон обязан вернуться в главный цикл и обработать сигналы. */
    for (int i = 0; i < 256; i++) {
        int     pkttype = -1;
        ssize_t n = cap_read(c->fd, c->buf, sizeof(c->buf), &pkttype);
        if (n <= 0) break;
        handled += scap_handle(c, c->buf, (size_t)n, pkttype, now, cb, ctx);
    }

    return handled;
}
