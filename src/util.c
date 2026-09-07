#include "util.h"

#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

char *str_trim(char *s)
{
    if (!s) return NULL;

    while (*s && isspace((unsigned char)*s)) s++;
    if (!*s) return s;

    char *end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) *end-- = '\0';
    return s;
}

int str_copy(char *dst, size_t dst_size, const char *src)
{
    if (!dst || dst_size == 0) return -1;
    if (!src) { dst[0] = '\0'; return -1; }

    size_t len = strlen(src);
    if (len >= dst_size) {
        memcpy(dst, src, dst_size - 1);
        dst[dst_size - 1] = '\0';
        return -1;                      /* усечено */
    }
    memcpy(dst, src, len + 1);
    return 0;
}

int parse_bool(const char *s, int def)
{
    if (!s || !*s) return def;

    if (!strcasecmp(s, "1")   || !strcasecmp(s, "true") ||
        !strcasecmp(s, "yes") || !strcasecmp(s, "on")   ||
        !strcasecmp(s, "да"))
        return 1;

    if (!strcasecmp(s, "0")   || !strcasecmp(s, "false") ||
        !strcasecmp(s, "no")  || !strcasecmp(s, "off")   ||
        !strcasecmp(s, "нет"))
        return 0;

    return def;
}

int mkdir_p(const char *path, unsigned mode)
{
    if (!path || !*path) return -1;

    char buf[512];
    if (str_copy(buf, sizeof(buf), path) != 0) return -1;

    for (char *p = buf + 1; *p; p++) {
        if (*p != '/') continue;
        *p = '\0';
        if (mkdir(buf, mode) != 0 && errno != EEXIST) return -1;
        *p = '/';
    }
    if (mkdir(buf, mode) != 0 && errno != EEXIST) return -1;
    return 0;
}

int pidfile_write(const char *path)
{
    if (!path || !*path) return -1;

    char dir[512];
    if (str_copy(dir, sizeof(dir), path) != 0) return -1;
    char *slash = strrchr(dir, '/');
    if (slash) {
        *slash = '\0';
        if (mkdir_p(dir, 0755) != 0) return -1;
    }

    FILE *f = fopen(path, "w");
    if (!f) return -1;
    fprintf(f, "%ld\n", (long)getpid());
    fclose(f);
    return 0;
}

void pidfile_remove(const char *path)
{
    if (path && *path) unlink(path);
}

int pidfile_read_alive(const char *path)
{
    if (!path || !*path) return 0;

    FILE *f = fopen(path, "r");
    if (!f) return 0;

    long pid = 0;
    int  got = fscanf(f, "%ld", &pid);
    fclose(f);

    if (got != 1 || pid <= 0) return 0;
    if (kill((pid_t)pid, 0) != 0 && errno == ESRCH) return 0;
    return (int)pid;
}

int iface_ipv4(const char *iface, char *dst, size_t dst_size)
{
    if (!iface || !*iface || !dst || dst_size < INET_ADDRSTRLEN) return 0;
    dst[0] = '\0';

    struct ifaddrs *list = NULL;
    if (getifaddrs(&list) != 0) return 0;

    int found = 0;
    for (struct ifaddrs *a = list; a; a = a->ifa_next) {
        if (!a->ifa_addr || a->ifa_addr->sa_family != AF_INET) continue;
        if (!a->ifa_name || strcmp(a->ifa_name, iface) != 0) continue;

        const struct sockaddr_in *sin = (const struct sockaddr_in *)(const void *)a->ifa_addr;
        if (inet_ntop(AF_INET, &sin->sin_addr, dst, (socklen_t)dst_size)) {
            found = 1;
            break;
        }
    }

    freeifaddrs(list);
    return found;
}

int file_tail(const char *path, char *last, size_t size, long *lines)
{
    if (last && size) last[0] = '\0';
    if (lines) *lines = 0;

    FILE *f = fopen(path, "r");
    if (!f) return 0;

    /* Читаем кусками: строка длиннее буфера приходит частями. Считаем
       строку по её началу — так и длинная считается один раз, и
       последняя без перевода строки не теряется, а пустые не в счёт.
       Запоминаем первый кусок, чтобы в хвосте была голова строки. */
    char chunk[512];
    long n = 0;
    int  at_start = 1;

    while (fgets(chunk, sizeof(chunk), f)) {
        size_t len = strlen(chunk);

        if (at_start && chunk[0] != '\n') {
            n++;
            if (last && size) str_copy(last, size, chunk);
        }
        at_start = len && chunk[len - 1] == '\n';
    }
    fclose(f);

    if (last && size) str_trim(last);
    if (lines) *lines = n;
    return 1;
}
