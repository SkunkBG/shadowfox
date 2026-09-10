#include "sockrtt.h"

#include <stdint.h>
#include <string.h>

/* Раскладки netlink и inet_diag описаны здесь сами: заголовки Linux
   на macOS нет, а разбор должен собираться и проверяться везде. Это
   стабильный ABI ядра, он не менялся с 3.3. */
#define NL_REQUEST   0x001
#define NL_DUMP      0x300
#define NL_DONE      3
#define NL_ERROR     2
#define NL_SOCK_DIAG 4
#define DIAG_BY_FAMILY 20
#define DIAG_INFO    2          /* атрибут INET_DIAG_INFO: struct tcp_info */
#define TCP_ESTABLISHED_BIT (1u << 1)
#define TCPI_RTT_OFF 68         /* смещение tcpi_rtt в struct tcp_info */

struct nl_hdr  { uint32_t len; uint16_t type; uint16_t flags; uint32_t seq; uint32_t pid; };
struct sockid  { uint16_t sport, dport; uint32_t src[4], dst[4]; uint32_t ifindex; uint32_t cookie[2]; };
struct diag_req { uint8_t family, protocol, ext, pad; uint32_t states; struct sockid id; };
struct diag_msg { uint8_t family, state, timer, retrans; struct sockid id;
                  uint32_t expires, rqueue, wqueue, uid, inode; };
struct rta     { uint16_t len, type; };

#define ALIGN4(x) (((x) + 3u) & ~3u)

static int has_inode(unsigned long inode, const unsigned long *inodes, int n)
{
    for (int i = 0; i < n; i++) if (inodes[i] == inode) return 1;
    return 0;
}

static int has_port(int port, const int *ports, int n)
{
    for (int i = 0; i < n; i++) if (ports[i] == port) return 1;
    return 0;
}

int sockrtt_parse(const unsigned char *buf, size_t len,
                  const unsigned long *inodes, int n_inodes,
                  const int *ports, int n_ports, sockrtt_t *out)
{
    if (!buf || !out) return 0;
    int seen = 0;
    size_t off = 0;

    while (off + sizeof(struct nl_hdr) <= len) {
        struct nl_hdr h;
        memcpy(&h, buf + off, sizeof(h));
        if (h.len < sizeof(struct nl_hdr) || off + h.len > len) break;
        if (h.type == NL_DONE || h.type == NL_ERROR) break;

        size_t body = off + sizeof(struct nl_hdr);
        if (h.type == DIAG_BY_FAMILY && h.len >= sizeof(struct nl_hdr) + sizeof(struct diag_msg)) {
            struct diag_msg m;
            memcpy(&m, buf + body, sizeof(m));
            /* Порт в sockid — сетевой порядок байт, как в самом ядре. */
            int dport = (int)(((unsigned)((const unsigned char *)&m.id.dport)[0] << 8) |
                               ((const unsigned char *)&m.id.dport)[1]);

            if (has_inode(m.inode, inodes, n_inodes) && has_port(dport, ports, n_ports)) {
                size_t a = body + ALIGN4(sizeof(struct diag_msg));
                size_t end = off + h.len;
                while (a + sizeof(struct rta) <= end) {
                    struct rta r;
                    memcpy(&r, buf + a, sizeof(r));
                    if (r.len < sizeof(struct rta) || a + r.len > end) break;
                    if (r.type == DIAG_INFO && r.len >= sizeof(struct rta) + TCPI_RTT_OFF + 4) {
                        uint32_t rtt;
                        memcpy(&rtt, buf + a + sizeof(struct rta) + TCPI_RTT_OFF, 4);
                        if (rtt > 0) {
                            out->count++;
                            out->sum_us += rtt;
                            if (!out->min_us || rtt < out->min_us) out->min_us = rtt;
                            seen++;
                        }
                        break;
                    }
                    a += ALIGN4(r.len);
                }
            }
        }
        off += ALIGN4(h.len);
    }
    return seen;
}

int sockrtt_ms(const sockrtt_t *r)
{
    if (!r || r->count <= 0) return -1;
    return (int)((r->sum_us / (unsigned long)r->count + 500) / 1000);
}

#ifdef __linux__
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

static int dump_family(int fd, uint8_t family,
                       const unsigned long *inodes, int n_inodes,
                       const int *ports, int n_ports, sockrtt_t *out)
{
    struct { struct nl_hdr h; struct diag_req r; } req;
    memset(&req, 0, sizeof(req));
    req.h.len    = sizeof(req);
    req.h.type   = DIAG_BY_FAMILY;
    req.h.flags  = NL_REQUEST | NL_DUMP;
    req.h.seq    = (uint32_t)family;
    req.r.family = family;
    req.r.protocol = 6;                    /* IPPROTO_TCP */
    req.r.ext    = 1u << (DIAG_INFO - 1);  /* просим tcp_info */
    req.r.states = TCP_ESTABLISHED_BIT;

    if (send(fd, &req, sizeof(req), 0) != (ssize_t)sizeof(req)) return -1;

    static unsigned char buf[64 * 1024];
    for (int round = 0; round < 64; round++) {
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) return -1;
        sockrtt_parse(buf, (size_t)n, inodes, n_inodes, ports, n_ports, out);

        /* Конец пачки — NLMSG_DONE или ошибка в этом же куске. */
        size_t off = 0;
        while (off + sizeof(struct nl_hdr) <= (size_t)n) {
            struct nl_hdr h;
            memcpy(&h, buf + off, sizeof(h));
            if (h.len < sizeof(struct nl_hdr)) return 0;
            if (h.type == NL_DONE)  return 0;
            if (h.type == NL_ERROR) return -1;
            off += ALIGN4(h.len);
        }
    }
    return 0;
}

int sockrtt_collect(const unsigned long *inodes, int n_inodes,
                    const int *ports, int n_ports, sockrtt_t *out)
{
    if (!out) return -1;
    memset(out, 0, sizeof(*out));

    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NL_SOCK_DIAG);
    if (fd < 0) return -1;
    struct timeval tv = { 2, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    int rc4 = dump_family(fd, 2  /* AF_INET  */, inodes, n_inodes, ports, n_ports, out);
    int rc6 = dump_family(fd, 10 /* AF_INET6 */, inodes, n_inodes, ports, n_ports, out);
    close(fd);
    return (rc4 == 0 || rc6 == 0) ? 0 : -1;
}
#else
int sockrtt_collect(const unsigned long *inodes, int n_inodes,
                    const int *ports, int n_ports, sockrtt_t *out)
{
    (void)inodes; (void)n_inodes; (void)ports; (void)n_ports;
    if (out) memset(out, 0, sizeof(*out));
    return -1;
}
#endif
