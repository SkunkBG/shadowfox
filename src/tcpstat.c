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
    if (read_file("/proc/net/tcp", text, sizeof(text)) > 0) {
        tcpstat_parse(text, inodes, n, ports, n_ports, &part);
        out->established += part.established;
        out->syn_sent    += part.syn_sent;
        out->retrans     += part.retrans;
    }
    if (read_file("/proc/net/tcp6", text, sizeof(text)) > 0) {
        tcpstat_parse(text, inodes, n, ports, n_ports, &part);
        out->established += part.established;
        out->syn_sent    += part.syn_sent;
        out->retrans     += part.retrans;
    }
    return 0;
}
