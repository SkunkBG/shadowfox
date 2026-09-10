/* Задержка по SYN/SYN-ACK: собираем IP-пакеты руками. Проверяем отбор по
   адресу сервера и порту (после NAT источник ничего не значит),
   зеркальный кортеж, повторы SYN, окно свежести и медиану. */
#include "rttcap.h"
#include "tcpstat.h"
#include "shadowfox.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond, ...)                                     \
    do {                                                     \
        if (!(cond)) {                                       \
            printf("  ПРОВАЛ %s:%d: ", __FILE__, __LINE__);  \
            printf(__VA_ARGS__);                             \
            printf("\n");                                    \
            failures++;                                      \
        }                                                    \
    } while (0)

static size_t v4(unsigned char *p, const unsigned char *src, const unsigned char *dst,
                 int sport, int dport, unsigned flags)
{
    memset(p, 0, 40);
    p[0] = 0x45; p[9] = 6;
    memcpy(p + 12, src, 4); memcpy(p + 16, dst, 4);
    p[20] = (unsigned char)(sport >> 8); p[21] = (unsigned char)sport;
    p[22] = (unsigned char)(dport >> 8); p[23] = (unsigned char)dport;
    p[32] = 0x50; p[33] = (unsigned char)flags;
    return 40;
}

static size_t v6(unsigned char *p, const unsigned char *src, const unsigned char *dst,
                 int sport, int dport, unsigned flags)
{
    memset(p, 0, 60);
    p[0] = 0x60; p[6] = 6;
    memcpy(p + 8, src, 16); memcpy(p + 24, dst, 16);
    p[40] = (unsigned char)(sport >> 8); p[41] = (unsigned char)sport;
    p[42] = (unsigned char)(dport >> 8); p[43] = (unsigned char)dport;
    p[52] = 0x50; p[53] = (unsigned char)flags;
    return 60;
}

int main(void)
{
    printf("check_rttcap %s\n", VERSION);

    static rttcap_t c;
    rttcap_init(&c);
    int ports[] = { 443 };
    rttcap_set_ports(&c, ports, 1);

    unsigned char server[16] = { 203, 0, 113, 10 };
    unsigned char router[16] = { 100, 64, 1, 2 };
    unsigned char other[16]  = { 198, 51, 100, 7 };
    unsigned char fam = 4;
    rttcap_set_targets(&c, (const unsigned char (*)[16])server, &fam, 1);

    unsigned char pkt[64];
    size_t n;

    /* SYN к серверу в t=0, SYN-ACK через 42 мс. */
    n = v4(pkt, router, server, 50000, 443, 0x02);
    CHECK(rttcap_feed(&c, pkt, n, 1000000, 100) == 0, "SYN — ещё не замер");
    n = v4(pkt, server, router, 443, 50000, 0x12);
    CHECK(rttcap_feed(&c, pkt, n, 1042000, 100) == 1, "SYN-ACK даёт замер");
    CHECK(rttcap_ms(&c, 100) == 42, "42 мс: %d", rttcap_ms(&c, 100));

    /* Чужой сервер на тот же порт — мимо. */
    n = v4(pkt, router, other, 50001, 443, 0x02);
    rttcap_feed(&c, pkt, n, 2000000, 101);
    n = v4(pkt, other, router, 443, 50001, 0x12);
    CHECK(rttcap_feed(&c, pkt, n, 2005000, 101) == 0, "чужой адрес не считается");

    /* Чужой порт на адрес сервера — мимо. */
    n = v4(pkt, router, server, 50002, 80, 0x02);
    rttcap_feed(&c, pkt, n, 3000000, 102);
    n = v4(pkt, server, router, 80, 50002, 0x12);
    CHECK(rttcap_feed(&c, pkt, n, 3005000, 102) == 0, "чужой порт не считается");

    /* Повтор SYN: время берётся от последнего. */
    n = v4(pkt, router, server, 50003, 443, 0x02);
    rttcap_feed(&c, pkt, n, 4000000, 103);
    rttcap_feed(&c, pkt, n, 5000000, 104);
    n = v4(pkt, server, router, 443, 50003, 0x12);
    CHECK(rttcap_feed(&c, pkt, n, 5030000, 104) == 1, "после повтора замер есть");
    CHECK(rttcap_ms(&c, 104) == 42, "медиана из 42 и 30 — верхняя из двух: %d", rttcap_ms(&c, 104));

    /* SYN-ACK без SYN — мимо; RST — мимо. */
    n = v4(pkt, server, router, 443, 50009, 0x12);
    CHECK(rttcap_feed(&c, pkt, n, 6000000, 105) == 0, "SYN-ACK без SYN");
    n = v4(pkt, router, server, 50010, 443, 0x06);
    CHECK(rttcap_feed(&c, pkt, n, 6000000, 105) == 0, "RST не считается");

    /* IPv6. */
    unsigned char s6[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    unsigned char r6[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };
    unsigned char fams[2] = { 4, 6 };
    unsigned char tg[2][16];
    memcpy(tg[0], server, 16); memcpy(tg[1], s6, 16);
    rttcap_set_targets(&c, (const unsigned char (*)[16])tg, fams, 2);
    n = v6(pkt, r6, s6, 50020, 443, 0x02);
    rttcap_feed(&c, pkt, n, 7000000, 106);
    n = v6(pkt, s6, r6, 443, 50020, 0x12);
    CHECK(rttcap_feed(&c, pkt, n, 7100000, 106) == 1, "IPv6 замер");

    /* Старые замеры выпадают из окна. */
    CHECK(rttcap_ms(&c, 106 + RTTCAP_STALE_SEC + 1) == -1, "устарело — нет данных");

    /* Адреса из /proc/net/tcp: little-endian образ 203.0.113.10 = 0A7100CB. */
    tcpstat_t st;
    unsigned long inodes[] = { 77 };
    const char *text =
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        "   0: 0201406400000000:C350 0A7100CB:01BB 01 00000000:00000000 00:00000000 00000000     0        0 77 1\n"
        "   1: 0201406400000000:C351 0A7100CB:01BB 02 00000000:00000000 00:00000000 00000000     0        0 77 1\n"
        "   2: 0201406400000000:C352 07643DC6:01BB 01 00000000:00000000 00:00000000 00000000     0        0 78 1\n";
    tcpstat_parse(text, inodes, 1, ports, 1, &st);
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    CHECK(st.remote_count == 1, "адрес один (BE, порядок иной): %d", st.remote_count);
#else
    CHECK(st.remote_count == 1 && st.remote_fam[0] == 4 && !memcmp(st.remotes[0], server, 4),
          "адрес сервера из /proc: %d %u.%u.%u.%u", st.remote_count,
          st.remotes[0][0], st.remotes[0][1], st.remotes[0][2], st.remotes[0][3]);
#endif

    if (failures) { printf("  провалов: %d\n", failures); return 1; }
    printf("все проверки пройдены\n");
    return 0;
}
