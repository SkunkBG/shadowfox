/* Разбор ответа sock_diag: собираем пачку netlink-сообщений руками, как
   их отдаёт ядро, и проверяем отбор по inode и порту, чтение tcpi_rtt
   и остановку на NLMSG_DONE. */
#include "sockrtt.h"
#include "shadowfox.h"

#include <stdint.h>
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

static unsigned char buf[4096];
static size_t used;

static void put32(uint32_t v) { memcpy(buf + used, &v, 4); used += 4; }
static void put16(uint16_t v) { memcpy(buf + used, &v, 2); used += 2; }
static void put8(uint8_t v)   { buf[used++] = v; }
static void pad4(void)        { while (used & 3) buf[used++] = 0; }

/* Одно сообщение SOCK_DIAG_BY_FAMILY: diag_msg + атрибут INET_DIAG_INFO
   с tcp_info, где заполнен только tcpi_rtt. */
static void msg(uint32_t inode, int dport, uint32_t rtt_us, int with_info)
{
    size_t start = used;
    put32(0);                     /* len, заполним позже */
    put16(20); put16(0x302);      /* type, flags (MULTI|DUMP) */
    put32(1);  put32(0);          /* seq, pid */
    /* diag_msg */
    put8(2); put8(1); put8(0); put8(0);          /* family, state, timer, retrans */
    put16(0x1234);                               /* sport */
    put16((uint16_t)(((dport & 0xff) << 8) | (dport >> 8)));   /* dport, сетевой порядок */
    for (int i = 0; i < 4; i++) put32(0);        /* src */
    for (int i = 0; i < 4; i++) put32(0);        /* dst */
    put32(0); put32(0); put32(0);                /* ifindex, cookie */
    put32(0); put32(0); put32(0); put32(0);      /* expires, rqueue, wqueue, uid */
    put32(inode);
    pad4();
    if (with_info) {
        size_t a = used;
        put16(0); put16(2);                      /* rta len, type=INET_DIAG_INFO */
        size_t info = used;
        for (int i = 0; i < 104; i++) put8(0);   /* tcp_info, 104 байта хватает */
        memcpy(buf + info + 68, &rtt_us, 4);     /* tcpi_rtt */
        uint16_t rlen = (uint16_t)(used - a);
        memcpy(buf + a, &rlen, 2);
        pad4();
    }
    uint32_t len = (uint32_t)(used - start);
    memcpy(buf + start, &len, 4);
}

static void done(void)
{
    size_t start = used;
    put32(20); put16(3); put16(0x2); put32(1); put32(0);   /* NLMSG_DONE */
    put32(0);
    (void)start;
}

int main(void)
{
    printf("check_sockrtt %s\n", VERSION);

    unsigned long inodes[] = { 1001, 1002 };
    int ports[] = { 443, 8443 };

    used = 0;
    msg(1001, 443, 40000, 1);     /* своё, 40 мс */
    msg(1002, 8443, 60000, 1);    /* своё, 60 мс */
    msg(9999, 443, 5000, 1);      /* чужой inode — мимо */
    msg(1001, 80, 7000, 1);       /* чужой порт — мимо */
    msg(1002, 443, 0, 1);         /* RTT ещё не измерен — мимо */
    msg(1001, 443, 0, 0);         /* без tcp_info — мимо */
    done();
    msg(1001, 443, 1000, 1);      /* после DONE не читается */

    sockrtt_t r;
    memset(&r, 0, sizeof(r));
    int n = sockrtt_parse(buf, used, inodes, 2, ports, 2, &r);
    CHECK(n == 2, "учтено два соединения: %d", n);
    CHECK(r.count == 2 && r.sum_us == 100000 && r.min_us == 40000,
          "сумма и минимум: %d %lu %lu", r.count, r.sum_us, r.min_us);
    CHECK(sockrtt_ms(&r) == 50, "среднее 50 мс: %d", sockrtt_ms(&r));

    sockrtt_t empty;
    memset(&empty, 0, sizeof(empty));
    CHECK(sockrtt_ms(&empty) == -1, "нет данных — -1");

    /* Обрезанный буфер не читается за границу. */
    memset(&r, 0, sizeof(r));
    n = sockrtt_parse(buf, 50, inodes, 2, ports, 2, &r);
    CHECK(n == 0, "обрезанное сообщение пропущено: %d", n);

    if (failures) { printf("  провалов: %d\n", failures); return 1; }
    printf("все проверки пройдены\n");
    return 0;
}
