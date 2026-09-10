#include "rttcap.h"
#include "log.h"
#include "util.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void rttcap_init(rttcap_t *c)
{
    if (!c) return;
    memset(c, 0, sizeof(*c));
    c->fd = -1;
}

void rttcap_set_ports(rttcap_t *c, const int *ports, int n)
{
    if (!c) return;
    c->port_count = 0;
    for (int i = 0; i < n && c->port_count < 32; i++) c->ports[c->port_count++] = ports[i];
}

void rttcap_set_targets(rttcap_t *c, const unsigned char (*addrs)[16],
                        const unsigned char *fams, int n)
{
    if (!c) return;
    c->target_count = 0;
    for (int i = 0; i < n && c->target_count < RTTCAP_TARGETS_MAX; i++) {
        memcpy(c->targets[c->target_count], addrs[i], 16);
        c->target_fam[c->target_count++] = fams[i];
    }
}

static int has_port(const rttcap_t *c, int port)
{
    for (int i = 0; i < c->port_count; i++) if (c->ports[i] == port) return 1;
    return 0;
}

static int is_target(const rttcap_t *c, unsigned char fam, const unsigned char *addr)
{
    for (int i = 0; i < c->target_count; i++)
        if (c->target_fam[i] == fam && !memcmp(c->targets[i], addr, 16)) return 1;
    return 0;
}

int rttcap_feed(rttcap_t *c, const unsigned char *pkt, size_t len,
                uint64_t now_us, time_t now)
{
    if (!c || !pkt || len < 40) return 0;

    unsigned char fam, src[16], dst[16];
    size_t tcp;
    if ((pkt[0] >> 4) == 4) {
        size_t ihl = (size_t)(pkt[0] & 0x0f) * 4;
        if (ihl < 20 || len < ihl + 20 || pkt[9] != 6) return 0;
        if ((((unsigned)pkt[6] << 8) | pkt[7]) & 0x1fff) return 0;   /* фрагмент */
        fam = 4;
        memset(src, 0, 16); memcpy(src, pkt + 12, 4);
        memset(dst, 0, 16); memcpy(dst, pkt + 16, 4);
        tcp = ihl;
    } else if ((pkt[0] >> 4) == 6) {
        if (len < 60 || pkt[6] != 6) return 0;
        fam = 6;
        memcpy(src, pkt + 8, 16);
        memcpy(dst, pkt + 24, 16);
        tcp = 40;
    } else {
        return 0;
    }

    const unsigned char *t = pkt + tcp;
    uint16_t sport = (uint16_t)((t[0] << 8) | t[1]);
    uint16_t dport = (uint16_t)((t[2] << 8) | t[3]);
    unsigned flags = t[13];
    int syn = (flags & 0x02) != 0, ack = (flags & 0x10) != 0, rst = (flags & 0x04) != 0;
    if (!syn || rst) return 0;

    if (!ack) {
        /* Исходящий SYN к серверу. */
        if (!has_port(c, dport) || !is_target(c, fam, dst)) return 0;
        c->seen_syn++;
        /* Тот же кортеж уже ждёт (повтор SYN) — обновляем время. */
        for (int i = 0; i < RTTCAP_PENDING_MAX; i++) {
            if (c->pending[i].at_us && c->pending[i].fam == fam &&
                c->pending[i].sport == sport && c->pending[i].dport == dport &&
                !memcmp(c->pending[i].src, src, 16) && !memcmp(c->pending[i].dst, dst, 16)) {
                c->pending[i].at_us = now_us;
                return 0;
            }
        }
        int k = c->pending_next++ % RTTCAP_PENDING_MAX;
        c->pending[k].fam   = fam;
        c->pending[k].sport = sport;
        c->pending[k].dport = dport;
        c->pending[k].at_us = now_us;
        memcpy(c->pending[k].src, src, 16);
        memcpy(c->pending[k].dst, dst, 16);
        return 0;
    }

    /* SYN-ACK от сервера: ищем ожидающий SYN с зеркальным кортежем. */
    if (!has_port(c, sport) || !is_target(c, fam, src)) return 0;
    c->seen_synack++;
    for (int i = 0; i < RTTCAP_PENDING_MAX; i++) {
        if (!c->pending[i].at_us || c->pending[i].fam != fam) continue;
        if (c->pending[i].sport != dport || c->pending[i].dport != sport) continue;
        if (memcmp(c->pending[i].src, dst, 16) || memcmp(c->pending[i].dst, src, 16)) continue;

        uint64_t dt = now_us >= c->pending[i].at_us ? now_us - c->pending[i].at_us : 0;
        c->pending[i].at_us = 0;
        /* Дольше 10 с — это не рукопожатие, а повтор после потерь. */
        if (dt == 0 || dt > 10000000ull) return 0;
        int ms = (int)((dt + 500) / 1000);
        int s  = c->samples_next++ % RTTCAP_SAMPLES_MAX;
        c->samples[s].ms = ms;
        c->samples[s].at = now;
        c->matched++;
        return 1;
    }
    return 0;
}

int rttcap_ms(const rttcap_t *c, time_t now)
{
    if (!c) return -1;
    int vals[RTTCAP_SAMPLES_MAX], n = 0;
    for (int i = 0; i < RTTCAP_SAMPLES_MAX; i++)
        if (c->samples[i].at && now - c->samples[i].at <= RTTCAP_STALE_SEC)
            vals[n++] = c->samples[i].ms;
    if (!n) return -1;
    /* медиана: вставками, значений мало */
    for (int i = 1; i < n; i++) {
        int v = vals[i], j = i - 1;
        while (j >= 0 && vals[j] > v) { vals[j + 1] = vals[j]; j--; }
        vals[j + 1] = v;
    }
    return vals[n / 2];
}

#ifdef __linux__

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <sys/socket.h>

/* Фильтр ядра: только TCP с флагом SYN, IPv4 и IPv6, без фрагментов.
   Для SOCK_DGRAM данные начинаются с IP-заголовка (см. dnscap.c). */
static struct sock_filter SYN_FILTER[] = {
    { 0x30, 0, 0,  0x00000000 },   /*  0: версия IP */
    { 0x54, 0, 0,  0x000000f0 },   /*  1 */
    { 0x15, 0, 4,  0x00000060 },   /*  2: IPv6? иначе → 7 */
    { 0x30, 0, 0,  0x00000006 },   /*  3: next header */
    { 0x15, 0, 13, 0x00000006 },   /*  4: TCP? иначе → 18 */
    { 0x30, 0, 0,  0x00000035 },   /*  5: флаги TCP (40+13) */
    { 0x45, 10, 11, 0x00000002 },  /*  6: SYN → 17, иначе → 18 */
    { 0x30, 0, 0,  0x00000000 },   /*  7 */
    { 0x54, 0, 0,  0x000000f0 },   /*  8 */
    { 0x15, 0, 8,  0x00000040 },   /*  9: IPv4? иначе → 18 */
    { 0x30, 0, 0,  0x00000009 },   /* 10: протокол */
    { 0x15, 0, 6,  0x00000006 },   /* 11: TCP? иначе → 18 */
    { 0x28, 0, 0,  0x00000006 },   /* 12: фрагмент */
    { 0x45, 4, 0,  0x00001fff },   /* 13: фрагмент → 18 */
    { 0xb1, 0, 0,  0x00000000 },   /* 14: X = длина IP-заголовка */
    { 0x50, 0, 0,  0x0000000d },   /* 15: флаги TCP [x+13] */
    { 0x45, 0, 1,  0x00000002 },   /* 16: SYN → 17, иначе → 18 */
    { 0x6,  0, 0,  0x00000060 },   /* 17: пропустить 96 байт */
    { 0x6,  0, 0,  0x00000000 },   /* 18: отбросить */
};

int rttcap_open(rttcap_t *c, char *err, size_t err_size)
{
    if (!c) return -1;
    rttcap_close(c);

    int fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL));
    if (fd < 0) {
        if (err) snprintf(err, err_size, "socket(AF_PACKET): %s", strerror(errno));
        return -1;
    }
    struct sock_fprog prog = {
        .len    = (unsigned short)(sizeof(SYN_FILTER) / sizeof(SYN_FILTER[0])),
        .filter = SYN_FILTER,
    };
    if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)) == 0)
        c->filtered = 1;
    else
        log_warn("фильтр SYN не принят ядром (%s), пакеты будут отбираться в демоне",
                 strerror(errno));

    /* Все интерфейсы: соединения ядра с сервером уходят через WAN, а
       какой он, зависит от настройки; SYN-ACK приходит там же. */
    fcntl(fd, F_SETFD, FD_CLOEXEC);
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    c->fd = fd;
    return 0;
}

static uint64_t mono_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ull + (uint64_t)ts.tv_nsec / 1000ull;
}

void rttcap_poll(rttcap_t *c, time_t now)
{
    if (!c || c->fd < 0) return;
    for (int i = 0; i < 256; i++) {
        ssize_t n = recv(c->fd, c->buf, sizeof(c->buf), MSG_DONTWAIT);
        if (n <= 0) break;
        rttcap_feed(c, c->buf, (size_t)n, mono_us(), now);
    }
}

#else

int rttcap_open(rttcap_t *c, char *err, size_t err_size)
{
    (void)c;
    if (err && err_size) str_copy(err, err_size, "наблюдение SYN есть только в Linux");
    return -1;
}

void rttcap_poll(rttcap_t *c, time_t now) { (void)c; (void)now; }

#endif

void rttcap_close(rttcap_t *c)
{
    if (c && c->fd >= 0) { close(c->fd); c->fd = -1; }
}
