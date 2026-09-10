#include "tcpstat.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int has_inode(const unsigned long *inodes, int n, unsigned long v)
{
    for (int i = 0; i < n; i++) if (inodes[i] == v) return 1;
    return 0;
}

static int has_port(const int *ports, int n, int v)
{
    for (int i = 0; i < n; i++) if (ports[i] == v) return 1;
    return 0;
}

/* Адрес из /proc/net/tcp: hex-образ слов __be32 в памяти. На little-
   endian байты каждого слова напечатаны задом наперёд, на big-endian —
   как есть. */
static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int decode_addr(const char *hex, size_t hexlen, unsigned char *dst, unsigned char *fam)
{
    if (hexlen != 8 && hexlen != 32) return 0;
    int words = (int)(hexlen / 8);
    for (int w = 0; w < words; w++) {
        for (int b = 0; b < 4; b++) {
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
            int src = b;
#else
            int src = 3 - b;
#endif
            int hi = hexval(hex[w * 8 + src * 2]), lo = hexval(hex[w * 8 + src * 2 + 1]);
            if (hi < 0 || lo < 0) return 0;
            dst[w * 4 + b] = (unsigned char)(hi * 16 + lo);
        }
    }
    if (words == 1) memset(dst + 4, 0, 12);
    *fam = words == 1 ? 4 : 6;
    return 1;
}

static void note_remote(tcpstat_t *out, const char *rem, size_t hexlen)
{
    unsigned char addr[16], fam;
    if (!decode_addr(rem, hexlen, addr, &fam)) return;
    for (int i = 0; i < out->remote_count; i++)
        if (out->remote_fam[i] == fam && !memcmp(out->remotes[i], addr, 16)) return;
    if (out->remote_count >= TCPSTAT_REMOTES_MAX) return;
    memcpy(out->remotes[out->remote_count], addr, 16);
    out->remote_fam[out->remote_count++] = fam;
}

int tcpstat_parse(const char *text, const unsigned long *inodes, int n_inodes,
                  const int *ports, int n_ports, tcpstat_t *out)
{
    if (!out) return 0;
    memset(out, 0, sizeof(*out));
    if (!text) return 0;

    int counted = 0;
    const char *p = text;

    while (*p) {
        const char *nl  = strchr(p, '\n');
        size_t      len = nl ? (size_t)(nl - p) : strlen(p);

        /* Формат строки:
           sl local_address rem_address st tx_queue:rx_queue tr:tm->when
           retrnsmt uid timeout inode ...
           Адреса в hex, порт после двоеточия; в tcp6 адрес длиннее,
           поэтому порт берём от конца поля, а не с фиксированной
           позиции. */
        char line[512];
        if (len >= sizeof(line)) { if (!nl) break; p = nl + 1; continue; }
        memcpy(line, p, len);
        line[len] = '\0';

        char  *save = NULL;
        char  *f[12];
        int    nf = 0;
        for (char *t = strtok_r(line, " \t", &save); t && nf < 12;
             t = strtok_r(NULL, " \t", &save))
            f[nf++] = t;

        if (nf >= 10 && strcmp(f[0], "sl") != 0) {
            const char *rem   = f[2];
            const char *colon = strrchr(rem, ':');
            unsigned    st    = (unsigned)strtoul(f[3], NULL, 16);
            unsigned long rt  = strtoul(f[6], NULL, 16);
            unsigned long ino = strtoul(f[9], NULL, 10);

            if (colon && has_inode(inodes, n_inodes, ino) &&
                has_port(ports, n_ports, (int)strtoul(colon + 1, NULL, 16))) {
                if (st == 0x01) { out->established++; out->retrans += rt; counted++; }
                else if (st == 0x02) { out->syn_sent++; counted++; }
                if (st == 0x01 || st == 0x02) note_remote(out, rem, (size_t)(colon - rem));
            }
        }

        if (!nl) break;
        p = nl + 1;
    }
    return counted;
}

int tcpstat_inodes(pid_t pid, unsigned long *inodes, int max)
{
    char dir[64];
    snprintf(dir, sizeof(dir), "/proc/%ld/fd", (long)pid);

    DIR *d = opendir(dir);
    if (!d) return -1;

    int n = 0;
    struct dirent *de;
    while ((de = readdir(d)) && n < max) {
        if (de->d_name[0] == '.') continue;

        /* Имя в fd — номер дескриптора, но компилятор считает по
           d_name целиком; отсечём заранее, чтобы не гадать. */
        if (strlen(de->d_name) > 16) continue;
        char path[128], link[64];
        snprintf(path, sizeof(path), "%.64s/%.16s", dir, de->d_name);
        ssize_t l = readlink(path, link, sizeof(link) - 1);
        if (l <= 0) continue;
        link[l] = '\0';

        if (strncmp(link, "socket:[", 8) == 0)
            inodes[n++] = strtoul(link + 8, NULL, 10);
    }
    closedir(d);
    return n;
}

static long read_file(const char *path, char *buf, size_t size)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    size_t got = fread(buf, 1, size - 1, f);
    fclose(f);
    buf[got] = '\0';
    return (long)got;
}

int tcpstat_collect(pid_t pid, const int *ports, int n_ports, tcpstat_t *out)
{
    static unsigned long inodes[TCPSTAT_INODES_MAX];
    static char          text[256 * 1024];

    memset(out, 0, sizeof(*out));
    int n = tcpstat_inodes(pid, inodes, TCPSTAT_INODES_MAX);
    if (n < 0) return -1;

    tcpstat_t part;
    const char *files[] = { "/proc/net/tcp", "/proc/net/tcp6" };
    for (int f = 0; f < 2; f++) {
        if (read_file(files[f], text, sizeof(text)) <= 0) continue;
        tcpstat_parse(text, inodes, n, ports, n_ports, &part);
        out->established += part.established;
        out->syn_sent    += part.syn_sent;
        out->retrans     += part.retrans;
        for (int i = 0; i < part.remote_count && out->remote_count < TCPSTAT_REMOTES_MAX; i++) {
            int dup = 0;
            for (int k = 0; k < out->remote_count; k++)
                if (out->remote_fam[k] == part.remote_fam[i] &&
                    !memcmp(out->remotes[k], part.remotes[i], 16)) dup = 1;
            if (dup) continue;
            memcpy(out->remotes[out->remote_count], part.remotes[i], 16);
            out->remote_fam[out->remote_count++] = part.remote_fam[i];
        }
    }
    return 0;
}
