#ifndef SHADOWFOX_RTTCAP_H
#define SHADOWFOX_RTTCAP_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

/* Задержка до сервера по живым соединениям, второй способ — для ядер
   без sock_diag (Keenetic 4.9-ndm). Наблюдаем SYN и SYN-ACK реальных
   соединений ядра Xray к серверу через AF_PACKET с фильтром ядра, как
   tcpdump: время между исходящим SYN и ответным SYN-ACK и есть RTT.
   Ни одного своего пакета не отправляется.

   После NAT на WAN-интерфейсе пакеты устройств из сети выглядят как
   пакеты роутера, поэтому отбор — по адресам серверов, к которым у
   ядра есть сокеты (см. tcpstat_t.remotes), и по портам. */

#define RTTCAP_PENDING_MAX 64
#define RTTCAP_SAMPLES_MAX 32
#define RTTCAP_TARGETS_MAX 16
#define RTTCAP_STALE_SEC   600     /* без новых замеров — данных нет */

typedef struct {
    int fd;                        /* -1 — не открыт */
    int filtered;                  /* фильтр ядра принят */

    unsigned char targets[RTTCAP_TARGETS_MAX][16];
    unsigned char target_fam[RTTCAP_TARGETS_MAX];
    int           target_count;
    int           ports[32];
    int           port_count;

    struct {
        unsigned char fam;
        unsigned char src[16], dst[16];
        uint16_t      sport, dport;
        uint64_t      at_us;
    } pending[RTTCAP_PENDING_MAX];
    int pending_next;

    struct { int ms; time_t at; } samples[RTTCAP_SAMPLES_MAX];
    int samples_next;

    unsigned long seen_syn, seen_synack, matched;
    unsigned char buf[256];
} rttcap_t;

void rttcap_init(rttcap_t *c);
int  rttcap_open(rttcap_t *c, char *err, size_t err_size);   /* только Linux */
void rttcap_close(rttcap_t *c);

void rttcap_set_ports(rttcap_t *c, const int *ports, int n);
void rttcap_set_targets(rttcap_t *c, const unsigned char (*addrs)[16],
                        const unsigned char *fams, int n);

/* Один IP-пакет (без канального заголовка), now_us — монотонные микро-
   секунды. Возвращает 1, если получился замер. Отдельно от сокета —
   ради тестов. */
int  rttcap_feed(rttcap_t *c, const unsigned char *pkt, size_t len,
                 uint64_t now_us, time_t now);

/* Забрать накопившиеся пакеты из сокета. */
void rttcap_poll(rttcap_t *c, time_t now);

/* Медиана замеров за последние RTTCAP_STALE_SEC, мс; -1 — нет данных. */
int  rttcap_ms(const rttcap_t *c, time_t now);

#endif
