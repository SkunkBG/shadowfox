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

int json_escape(const char *in, char *out, unsigned out_size)
{
    unsigned o = 0;

    for (const char *p = in; *p; p++) {
        unsigned char c = (unsigned char)*p;

        /* Управляющие символы в логине — заведомо мусор, а корректно
           закодировать их значило бы усложнять ради невозможного. */
        if (c < 0x20) return -1;

        if (c == '"' || c == '\\') {
            if (o + 2 >= out_size) return -1;
            out[o++] = '\\';
        } else if (o + 1 >= out_size) {
            return -1;
        }
        out[o++] = (char)c;
    }

    out[o] = '\0';
    return 0;
}

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

ndm_result_t ndm_begin(const char *host, int port, ndm_pending_t *out,
                       char *err, unsigned err_size)
{
    if (!host || !out) return NDM_UNAVAILABLE;
    memset(out, 0, sizeof(*out));

    char req[1024];
    /* User-Agent и Accept шлём намеренно: встроенные веб-серверы иногда
       отвечают 400 на запрос без них, а curl их подставляет сам — из-за
       чего проверка руками проходит, а наша нет. */
    int  n = snprintf(req, sizeof(req),
                      "GET /auth HTTP/1.1\r\nHost: %s\r\n"
                      "User-Agent: ShadowFox\r\nAccept: */*\r\n"
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

    /* Роутер разрешает вход не с любого адреса: с петли он отвечает
       отказом по уровню безопасности. Называем причину прямо — иначе
       она выглядит как «схема не та», и искать будут не там. */
    if (code == 403) {
        if (err)
            snprintf(err, err_size,
                     "роутер не принимает вход с адреса %s "
                     "— укажи в настройке routerHost адрес из своей сети", host);
        return NDM_UNAVAILABLE;
    }

    if (code != 401) {
        char d1[160] = "";
        ndm_header(resp, "X-Detail", d1, sizeof(d1));
        if (err) {
            if (d1[0]) snprintf(err, err_size, "роутер: %d, %s", code, d1);
            else       snprintf(err, err_size, "роутер ответил кодом %d на запрос входа", code);
        }
        return NDM_UNAVAILABLE;
    }

    if (!ndm_header(resp, "X-NDM-Realm", out->realm, sizeof(out->realm)) ||
        !ndm_header(resp, "X-NDM-Challenge", out->challenge, sizeof(out->challenge))) {
        if (err) str_copy(err, err_size, "роутер ответил не по своей схеме входа");
        return NDM_UNAVAILABLE;
    }

    /* Сессионная кука обязательна: challenge выдан именно ей. */
    ndm_header(resp, "Set-Cookie", out->cookie, sizeof(out->cookie));
    char *semi = strchr(out->cookie, ';');
    if (semi) *semi = '\0';

    return NDM_OK;
}

ndm_result_t ndm_finish(const char *host, int port, const ndm_pending_t *p,
                        const char *login, const char *answer,
                        char *err, unsigned err_size)
{
    if (!host || !p || !login || !answer) return NDM_UNAVAILABLE;

    /* Ответ — 64 шестнадцатеричных знака и ничего больше: он идёт в JSON
       и в заголовок, и это единственное, что приходит со страницы без
       нашего участия. */
    if (strlen(answer) != 64 || strspn(answer, "0123456789abcdef") != 64) {
        if (err) str_copy(err, err_size, "ответ на запрос не той формы");
        return NDM_DENIED;
    }

    /* Логин попадает в JSON, поэтому кавычки и обратные косые в нём
       надо экранировать: иначе тело перестанет быть разбираемым, а
       выглядеть это будет как неверный пароль. */
    char jlogin[256];
    if (json_escape(login, jlogin, sizeof(jlogin)) != 0) {
        if (err) str_copy(err, err_size, "слишком длинный логин");
        return NDM_UNAVAILABLE;
    }

    /* Логин с ответом идут телом JSON: прошивка 5.x отвечает на пустой
       POST «no data», а на форму — «bad content type». Заголовки
       X-NDM-* шлём вдобавок: на прошивках постарше работают только они,
       а новой они не мешают. */
    char body[512];
    int  n = snprintf(body, sizeof(body),
                      "{\"login\":\"%s\",\"password\":\"%s\"}", jlogin, answer);
    if (n < 0 || (size_t)n >= sizeof(body)) {
        if (err) str_copy(err, err_size, "слишком длинный логин");
        return NDM_UNAVAILABLE;
    }
    size_t blen = (size_t)n;

    char req[1024];
    n = snprintf(req, sizeof(req),
                 "POST /auth HTTP/1.1\r\nHost: %s\r\n"
                 "User-Agent: ShadowFox\r\nAccept: */*\r\n"
                 "X-NDM-Login: %s\r\nX-NDM-Password: %s\r\n"
                 "%s%s%s"
                 "Content-Type: application/json\r\n"
                 "Content-Length: %zu\r\nConnection: close\r\n\r\n%s",
                 host, login, answer,
                 p->cookie[0] ? "Cookie: " : "", p->cookie, p->cookie[0] ? "\r\n" : "",
                 blen, body);
    if (n < 0 || (size_t)n >= sizeof(req)) {
        if (err) str_copy(err, err_size, "слишком длинный логин");
        return NDM_UNAVAILABLE;
    }

    static char resp[8192];
    int code = exchange(host, port, req, resp, sizeof(resp));

    if (code == 200) return NDM_OK;
    if (code == 401 || code == 403) {
        if (err) str_copy(err, err_size, "неверный логин или пароль");
        return NDM_DENIED;
    }

    /* Роутер объясняет отказ заголовком X-Detail. Голый код заставляет
       гадать, а причина всё это время лежит в ответе. */
    char detail[160] = "";
    ndm_header(resp, "X-Detail", detail, sizeof(detail));

    if (err) {
        if (detail[0]) snprintf(err, err_size, "роутер: %d, %s", code, detail);
        else           snprintf(err, err_size, "роутер ответил кодом %d", code);
    }
    return NDM_UNAVAILABLE;
}

ndm_result_t ndm_check_password(const char *host, int port,
                                const char *login, const char *password,
                                char *err, unsigned err_size)
{
    if (!host || !login || !password) return NDM_UNAVAILABLE;

    ndm_pending_t p;
    ndm_result_t  r = ndm_begin(host, port, &p, err, err_size);
    if (r != NDM_OK) return r;

    char answer[65];
    ndm_answer(p.realm, p.challenge, login, password, answer);
    if (!answer[0]) {
        if (err) str_copy(err, err_size, "слишком длинный логин или пароль");
        return NDM_UNAVAILABLE;
    }

    return ndm_finish(host, port, &p, login, answer, err, err_size);
}
