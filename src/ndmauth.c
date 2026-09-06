#include "ndmauth.h"
#include "digest.h"
#include "util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

int ndm_header(const char *response, const char *name, char *out, unsigned out_size)
{
    if (!response || !name || !out || !out_size) return 0;

    size_t nlen = strlen(name);

    for (const char *p = response; *p; p++) {
        if (p != response && p[-1] != '\n') continue;
        if (strncasecmp(p, name, nlen) != 0) continue;

        const char *v = p + nlen;
        if (*v != ':') continue;
        v++;
        while (*v == ' ' || *v == '\t') v++;

        unsigned i = 0;
        while (v[i] && v[i] != '\r' && v[i] != '\n' && i + 1 < out_size) {
            out[i] = v[i];
            i++;
        }
        out[i] = '\0';
        return i > 0;
    }

    out[0] = '\0';
    return 0;
}

void ndm_answer(const char *realm, const char *challenge,
                const char *login, const char *password, char out[65])
{
    char first[512];
    int  n = snprintf(first, sizeof(first), "%s:%s:%s", login, realm, password);
    if (n < 0 || (size_t)n >= sizeof(first)) { out[0] = '\0'; return; }

    unsigned char m[16];
    char          mhex[33];
    md5(first, (size_t)n, m);
    hex_encode(m, sizeof(m), mhex);

    char second[512];
    n = snprintf(second, sizeof(second), "%s%s", challenge, mhex);
    if (n < 0 || (size_t)n >= sizeof(second)) { out[0] = '\0'; return; }

    unsigned char s[32];
    sha256(second, (size_t)n, s);
    hex_encode(s, sizeof(s), out);
}

static int dial(const char *host, int port, int seconds)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct timeval tv = { seconds, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port   = htons((unsigned short)port);
    if (inet_pton(AF_INET, host, &sa.sin_addr) != 1) { close(fd); return -1; }

    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) { close(fd); return -1; }
    return fd;
}

static int exchange(const char *host, int port, const char *request,
                    char *out, unsigned out_size)
{
    int fd = dial(host, port, 5);
    if (fd < 0) return -1;

    size_t len = strlen(request), off = 0;
    while (off < len) {
        ssize_t k = write(fd, request + off, len - off);
        if (k <= 0) { close(fd); return -1; }
        off += (size_t)k;
    }

    unsigned got = 0;
    while (got + 1 < out_size) {
        ssize_t k = read(fd, out + got, out_size - got - 1);
        if (k <= 0) break;
        got += (unsigned)k;
    }
    out[got] = '\0';
    close(fd);

    if (strncmp(out, "HTTP/1.", 7) != 0) return -1;
    return atoi(out + 9);
}

ndm_result_t ndm_check_password(const char *host, int port,
                                const char *login, const char *password,
                                char *err, unsigned err_size)
{
    if (!host || !login || !password) return NDM_UNAVAILABLE;

    /* С запасом: сюда складываются логин, ответ на запрос и кука
       сессии. Обрезанный запрос роутер отверг бы, а понять почему было
       бы неоткуда. */
    char req[1024];
    int  n = snprintf(req, sizeof(req),
                      "GET /auth HTTP/1.1\r\nHost: %s\r\n"
                      "Connection: close\r\n\r\n", host);
    if (n < 0 || (size_t)n >= sizeof(req)) {
        if (err) str_copy(err, err_size, "слишком длинный адрес роутера");
        return NDM_UNAVAILABLE;
    }

    static char resp[8192];
    int code = exchange(host, port, req, resp, sizeof(resp));

    if (code < 0) {
        if (err) snprintf(err, err_size, "роутер не ответил на %s:%d", host, port);
        return NDM_UNAVAILABLE;
    }

    /* 200 значит, что пароля у роутера нет вовсе: пускать всех в таком
       случае неправильно — лучше честно сказать, что проверить нечем. */
    if (code == 200) {
        if (err) str_copy(err, err_size, "на роутере не задан пароль администратора");
        return NDM_UNAVAILABLE;
    }

    char realm[128] = "", challenge[128] = "";
    if (!ndm_header(resp, "X-NDM-Realm", realm, sizeof(realm)) ||
        !ndm_header(resp, "X-NDM-Challenge", challenge, sizeof(challenge))) {
        if (err) str_copy(err, err_size, "роутер ответил не по своей схеме входа");
        return NDM_UNAVAILABLE;
    }

    char answer[65];
    ndm_answer(realm, challenge, login, password, answer);
    if (!answer[0]) {
        if (err) str_copy(err, err_size, "слишком длинный логин или пароль");
        return NDM_UNAVAILABLE;
    }

    /* Сессионная кука обязательна: challenge выдан именно ей. */
    char cookie[256] = "";
    ndm_header(resp, "Set-Cookie", cookie, sizeof(cookie));
    char *semi = strchr(cookie, ';');
    if (semi) *semi = '\0';

    n = snprintf(req, sizeof(req),
                 "POST /auth HTTP/1.1\r\nHost: %s\r\n"
                 "X-NDM-Login: %s\r\nX-NDM-Password: %s\r\n"
                 "%s%s%s"
                 "Content-Length: 0\r\nConnection: close\r\n\r\n",
                 host, login, answer,
                 cookie[0] ? "Cookie: " : "", cookie, cookie[0] ? "\r\n" : "");
    if (n < 0 || (size_t)n >= sizeof(req)) {
        if (err) str_copy(err, err_size, "слишком длинный логин");
        return NDM_UNAVAILABLE;
    }

    code = exchange(host, port, req, resp, sizeof(resp));

    if (code == 200) return NDM_OK;
    if (code == 401 || code == 403) {
        if (err) str_copy(err, err_size, "неверный логин или пароль");
        return NDM_DENIED;
    }

    if (err) snprintf(err, err_size, "роутер ответил кодом %d", code);
    return NDM_UNAVAILABLE;
}
