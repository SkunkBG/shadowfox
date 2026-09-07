#include "probe.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0   /* macOS: SIGPIPE и так игнорируется в main */
#endif

void probe_init(probe_t *p)
{
    memset(p, 0, sizeof(*p));
    p->fd = -1;
}

int probe_parse_url(const char *url, char *host, size_t host_size,
                    int *port, char *path, size_t path_size)
{
    if (!url || strncmp(url, "http://", 7) != 0) return -1;

    const char *h     = url + 7;
    const char *slash = strchr(h, '/');
    size_t      hlen  = slash ? (size_t)(slash - h) : strlen(h);
    if (!hlen || hlen >= host_size) return -1;

    char hp[PROBE_HOST_MAX];
    memcpy(hp, h, hlen);
    hp[hlen] = '\0';

    *port = 80;
    char *colon = strchr(hp, ':');
    if (colon) {
        *colon = '\0';
        char *end = NULL;
        long  v   = strtol(colon + 1, &end, 10);
        if (!end || *end || v <= 0 || v > 65535) return -1;
        *port = (int)v;
    }
    if (!hp[0] || strlen(hp) > 253) return -1;

    /* Имя уходит в SOCKS как есть, а в HTTP как заголовок Host: ни
       пробелам, ни управляющим символам там не место. */
    for (const char *c = hp; *c; c++)
        if (!((*c >= 'a' && *c <= 'z') || (*c >= 'A' && *c <= 'Z') ||
              (*c >= '0' && *c <= '9') || *c == '-' || *c == '.'))
            return -1;

    str_copy(host, host_size, hp);
    if (str_copy(path, path_size, slash ? slash : "/") != 0) return -1;
    for (const char *c = path; *c; c++)
        if ((unsigned char)*c <= ' ' || (unsigned char)*c >= 127) return -1;
    return 0;
}

static long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

static int finish(probe_t *p, int ok, const char *why)
{
    if (p->fd >= 0) close(p->fd);
    p->fd    = -1;
    p->state = PROBE_DONE;
    p->ok    = ok;
    str_copy(p->why, sizeof(p->why), why ? why : "");
    return 1;
}

static int fail_errno(probe_t *p, const char *what)
{
    char why[PROBE_WHY_MAX];
    snprintf(why, sizeof(why), "%s: %s", what, strerror(errno));
    return finish(p, 0, why);
}

/* Отправляем целиком или считаем неудачей: сообщения здесь короче
   любого буфера отправки, частичная запись означала бы, что сокет
   уже не в порядке. */
static int send_all(probe_t *p, const void *data, size_t len, const char *what)
{
    ssize_t n = send(p->fd, data, len, MSG_NOSIGNAL);
    if (n == (ssize_t)len) return 0;
    if (n < 0) { fail_errno(p, what); return -1; }
    finish(p, 0, what);
    return -1;
}

static int send_greeting(probe_t *p)
{
    static const unsigned char hello[] = { 0x05, 0x01, 0x00 };   /* без аутентификации */
    if (send_all(p, hello, sizeof(hello), "ядро не приняло приветствие SOCKS") != 0)
        return -1;
    p->state = PROBE_GREET;
    p->len   = 0;
    return 0;
}

int probe_start(probe_t *p, const char *proxy, int proxy_port,
                const char *url, long now)
{
    probe_abort(p);
    p->ok  = 0;
    p->ms  = 0;
    p->why[0] = '\0';

    if (probe_parse_url(url, p->host, sizeof(p->host), &p->port,
                        p->path, sizeof(p->path)) != 0) {
        str_copy(p->why, sizeof(p->why), "адрес проверки не разобран");
        return -1;
    }

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port   = htons((unsigned short)proxy_port);
    if (inet_pton(AF_INET, proxy, &sa.sin_addr) != 1) {
        str_copy(p->why, sizeof(p->why), "адрес ядра не разобран");
        return -1;
    }

    p->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (p->fd < 0) {
        snprintf(p->why, sizeof(p->why), "socket: %s", strerror(errno));
        return -1;
    }
    fcntl(p->fd, F_SETFD, FD_CLOEXEC);
    fcntl(p->fd, F_SETFL, fcntl(p->fd, F_GETFL, 0) | O_NONBLOCK);

    p->started = now;
    p->len     = 0;

    if (connect(p->fd, (struct sockaddr *)&sa, sizeof(sa)) == 0) {
        p->state = PROBE_CONNECT;
        if (send_greeting(p) != 0) return -1;
        return 0;
    }
    if (errno != EINPROGRESS) {
        char why[PROBE_WHY_MAX];
        snprintf(why, sizeof(why), "нет связи с ядром: %s", strerror(errno));
        close(p->fd);
        p->fd = -1;
        str_copy(p->why, sizeof(p->why), why);
        return -1;
    }
    p->state = PROBE_CONNECT;
    return 0;
}

int probe_fd(const probe_t *p)
{
    if (!p || p->fd < 0) return -1;
    return (p->state == PROBE_GREET || p->state == PROBE_REQUEST ||
            p->state == PROBE_HTTP) ? p->fd : -1;
}

/* Дочитывает в буфер. Возвращает 1 — есть новые байты, 0 — ждём,
   -1 — проверка завершена (соединение закрыто или ошибка). */
static int fill(probe_t *p, const char *eof_why)
{
    if (p->len >= sizeof(p->buf)) { finish(p, 0, "ответ длиннее ожидаемого"); return -1; }

    ssize_t n = recv(p->fd, p->buf + p->len, sizeof(p->buf) - p->len, 0);
    if (n > 0) { p->len += (size_t)n; return 1; }
    if (n == 0) { finish(p, 0, eof_why); return -1; }
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return 0;
    fail_errno(p, "чтение из ядра");
    return -1;
}

static const char *socks_reason(unsigned char rep)
{
    switch (rep) {
    case 0x01: return "общая ошибка SOCKS";
    case 0x02: return "правило запрещает";
    case 0x03: return "сеть недостижима";
    case 0x04: return "узел недостижим";
    case 0x05: return "соединение отклонено";
    case 0x06: return "TTL истёк";
    case 0x07: return "команда не поддерживается";
    case 0x08: return "тип адреса не поддерживается";
    default:   return "неизвестный код ответа";
    }
}

static int step_connect(probe_t *p)
{
    struct pollfd pf = { p->fd, POLLOUT, 0 };
    if (poll(&pf, 1, 0) <= 0) return 0;

    int       err = 0;
    socklen_t sl  = sizeof(err);
    if (getsockopt(p->fd, SOL_SOCKET, SO_ERROR, &err, &sl) != 0) err = errno;
    if (err) {
        char why[PROBE_WHY_MAX];
        snprintf(why, sizeof(why), "нет связи с ядром: %s", strerror(err));
        return finish(p, 0, why);
    }
    return send_greeting(p) != 0 ? 1 : 0;
}

static int step_greet(probe_t *p)
{
    int r = fill(p, "ядро закрыло соединение на приветствии");
    if (r < 0) return 1;
    if (p->len < 2) return 0;
    if (p->buf[0] != 0x05 || p->buf[1] != 0x00)
        return finish(p, 0, "ядро отвергло приветствие SOCKS");

    /* CONNECT к имени: резолвить будет ядро, на той стороне туннеля. */
    unsigned char req[4 + 1 + PROBE_HOST_MAX + 2];
    size_t hl = strlen(p->host), n = 0;
    req[n++] = 0x05; req[n++] = 0x01; req[n++] = 0x00; req[n++] = 0x03;
    req[n++] = (unsigned char)hl;
    memcpy(req + n, p->host, hl); n += hl;
    req[n++] = (unsigned char)(p->port >> 8);
    req[n++] = (unsigned char)(p->port & 0xff);

    if (send_all(p, req, n, "ядро не приняло запрос CONNECT") != 0) return 1;
    p->state = PROBE_REQUEST;
    p->len   = 0;
    return 0;
}

static int step_request(probe_t *p)
{
    int r = fill(p, "ядро закрыло соединение на CONNECT");
    if (r < 0) return 1;
    if (p->len < 4) return 0;
    if (p->buf[0] != 0x05) return finish(p, 0, "ответ ядра не SOCKS5");
    if (p->buf[1] != 0x00) {
        char why[PROBE_WHY_MAX];
        snprintf(why, sizeof(why), "узел не соединил: %s", socks_reason(p->buf[1]));
        return finish(p, 0, why);
    }

    size_t need;
    switch (p->buf[3]) {
    case 0x01: need = 4 + 4 + 2; break;
    case 0x04: need = 4 + 16 + 2; break;
    case 0x03: if (p->len < 5) return 0; need = 4 + 1 + p->buf[4] + 2; break;
    default:   return finish(p, 0, "ответ ядра не разобран");
    }
    if (p->len < need) return 0;

    char get[PROBE_PATH_MAX + PROBE_HOST_MAX + 96];
    int  gl = snprintf(get, sizeof(get),
                       "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: shadowfox-probe\r\n"
                       "Connection: close\r\n\r\n", p->path, p->host);
    if (gl <= 0 || (size_t)gl >= sizeof(get)) return finish(p, 0, "запрос не поместился");

    p->t0_ms = now_ms();
    if (send_all(p, get, (size_t)gl, "туннель не принял запрос") != 0) return 1;
    p->state = PROBE_HTTP;
    p->len   = 0;
    return 0;
}

static int step_http(probe_t *p)
{
    /* Так узнаётся мёртвый сервер: ядро отвечает на CONNECT сразу, не
       дожидаясь исходящего, и лишь потом, не достучавшись, закрывает
       соединение с нами — без единого байта ответа. */
    int r = fill(p, "туннель закрыл соединение без ответа");
    if (r < 0) return 1;

    unsigned char *nl = memchr(p->buf, '\n', p->len);
    if (!nl) return 0;

    long ms = now_ms() - p->t0_ms;
    p->ms   = (int)(ms < 0 ? 0 : (ms > 60000 ? 60000 : ms));

    /* Строка ответа: HTTP/1.x NNN ... */
    if (p->len < 12 || memcmp(p->buf, "HTTP/1.", 7) != 0)
        return finish(p, 0, "через туннель пришёл не HTTP");

    int code = atoi((const char *)p->buf + 9);
    if (code >= 200 && code < 400) return finish(p, 1, "");

    char why[PROBE_WHY_MAX];
    snprintf(why, sizeof(why), "ответ HTTP %d", code);
    return finish(p, 0, why);
}

int probe_poll(probe_t *p, long now)
{
    if (!p || p->state == PROBE_IDLE) return 0;
    if (p->state == PROBE_DONE) return 1;

    if (now - p->started >= PROBE_TIMEOUT) {
        const char *why = p->state == PROBE_HTTP
            ? "нет ответа через туннель за 10 с"
            : "ядро не ответило за 10 с";
        return finish(p, 0, why);
    }

    switch (p->state) {
    case PROBE_CONNECT: return step_connect(p);
    case PROBE_GREET:   return step_greet(p);
    case PROBE_REQUEST: return step_request(p);
    case PROBE_HTTP:    return step_http(p);
    default:            return 0;
    }
}

void probe_abort(probe_t *p)
{
    if (!p) return;
    if (p->fd >= 0) close(p->fd);
    p->fd    = -1;
    p->state = PROBE_IDLE;
    p->len   = 0;
}
