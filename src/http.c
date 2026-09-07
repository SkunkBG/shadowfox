#include "http.h"
#include "log.h"
#include "util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

void http_init(http_t *h)
{
    memset(h, 0, sizeof(*h));
    h->fd = -1;
}

int http_fd(const http_t *h)
{
    return h ? h->fd : -1;
}

static int copy_until(const char *src, size_t len, char stop,
                      char *dst, size_t dst_size)
{
    size_t i = 0;
    while (i < len && src[i] != stop && src[i] != ' ' &&
           src[i] != '\r' && src[i] != '\n') {
        if (i + 1 >= dst_size) return -1;
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
    return (int)i;
}

int http_parse_request(const char *buf, size_t len, http_req_t *out)
{
    if (!buf || !out || len < 4) return -1;
    memset(out, 0, sizeof(*out));

    /* Строка запроса: МЕТОД путь HTTP/версия */
    const char *sp = memchr(buf, ' ', len);
    if (!sp) return -1;

    size_t mlen = (size_t)(sp - buf);
    if (mlen == 0 || mlen >= sizeof(out->method)) return -1;
    memcpy(out->method, buf, mlen);
    out->method[mlen] = '\0';

    const char *p    = sp + 1;
    size_t      rest = len - (size_t)(p - buf);

    int n = copy_until(p, rest, '?', out->path, sizeof(out->path));
    if (n < 0 || !out->path[0]) return -1;

    if (p[n] == '?') {
        p    += n + 1;
        rest  = len - (size_t)(p - buf);
        if (copy_until(p, rest, '\0', out->query, sizeof(out->query)) < 0)
            return -1;
    }

    /* Тело идёт после пустой строки. */
    size_t      skip = 0;
    const char *sep  = http_headers_end(buf, len, &skip);

    /* Токен: заголовок Authorization целиком, без разбора схемы —
       сравнивать всё равно с одним заданным значением. */
    const char *hdr_end = sep ? sep : buf + len;

    for (const char *h = buf; h + 7 < hdr_end; h++) {
        if (h != buf && h[-1] != '\n') continue;
        if (strncasecmp(h, "Cookie:", 7) != 0) continue;

        const char *v = h + 7;
        while (v < hdr_end && (*v == ' ' || *v == '\t')) v++;

        const char *e = v;
        while (e < hdr_end && *e != '\r' && *e != '\n') e++;

        out->cookie     = v;
        out->cookie_len = (size_t)(e - v);
        break;
    }
    for (const char *h = buf; h + 14 < hdr_end; h++) {
        if (strncasecmp(h, "Authorization:", 14) != 0) continue;
        h += 14;
        while (h < hdr_end && (*h == ' ' || *h == '\t')) h++;
        /* Отбрасываем слово схемы, если оно есть. */
        const char *space = memchr(h, ' ', (size_t)(hdr_end - h));
        const char *val   = space ? space + 1 : h;
        copy_until(val, (size_t)(hdr_end - val), '\r',
                   out->token, sizeof(out->token));
        break;
    }

    out->declared_len = http_content_length(buf, (size_t)(hdr_end - buf));

    if (sep) {
        out->body     = sep + skip;
        out->body_len = len - (size_t)(out->body - buf);
    }

    return 0;
}

/* Конец заголовков. Вынесено из разбора: цикл приёма обязан узнать то же
   самое раньше, чем сможет разобрать запрос целиком. */
const char *http_headers_end(const char *buf, size_t len, size_t *skip)
{
    for (size_t i = 0; i + 1 < len; i++) {
        if (i + 3 < len && !memcmp(buf + i, "\r\n\r\n", 4)) {
            if (skip) *skip = 4;
            return buf + i;
        }
        if (!memcmp(buf + i, "\n\n", 2)) {
            if (skip) *skip = 2;
            return buf + i;
        }
    }
    return NULL;
}

/* Content-Length из заголовков. -1 — заголовка нет, -2 — он испорчен.
   Различать важно: у GET тела и не должно быть, а битую длину принимать
   нельзя, иначе запись пойдёт обрезанной. */
long http_content_length(const char *buf, size_t hdr_len)
{
    static const char key[] = "Content-Length:";
    const size_t      klen  = sizeof(key) - 1;

    for (size_t i = 0; i + klen < hdr_len; i++) {
        if (i && buf[i - 1] != '\n') continue;
        if (strncasecmp(buf + i, key, klen) != 0) continue;

        const char *v = buf + i + klen;
        const char *e = buf + hdr_len;
        while (v < e && (*v == ' ' || *v == '\t')) v++;
        if (v >= e || *v < '0' || *v > '9') return -2;

        long n = 0;
        for (; v < e && *v >= '0' && *v <= '9'; v++) {
            n = n * 10 + (*v - '0');
            if (n > (long)HTTP_BUF_BYTES) return -2;
        }
        return n;
    }
    return -1;
}

int http_query_get(const http_req_t *r, const char *key,
                   char *out, size_t out_size)
{
    if (!r || !key || !out || !out_size) return 0;
    out[0] = '\0';

    size_t klen = strlen(key);
    const char *p = r->query;

    while (*p) {
        const char *amp = strchr(p, '&');
        size_t      len = amp ? (size_t)(amp - p) : strlen(p);

        if (len > klen && p[klen] == '=' && strncmp(p, key, klen) == 0) {
            size_t vlen = len - klen - 1;
            if (vlen >= out_size) return 0;
            memcpy(out, p + klen + 1, vlen);
            out[vlen] = '\0';
            return 1;
        }

        if (!amp) break;
        p = amp + 1;
    }
    return 0;
}

int http_open(http_t *h, const char *addr, int port, char *err, unsigned err_size)
{
    if (!h) return -1;
    http_close(h);

    if (!addr || !*addr) {
        if (err) str_copy(err, err_size, "адрес не задан");
        return -1;
    }
    /* Слушать на всех интерфейсах нельзя: у neofit так получался
       доступ к управлению роутером с любой стороны. */
    if (!strcmp(addr, "0.0.0.0") || !strcmp(addr, "*")) {
        if (err) str_copy(err, err_size, "слушать 0.0.0.0 запрещено");
        return -1;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        if (err) snprintf(err, err_size, "socket: %s", strerror(errno));
        return -1;
    }

    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port   = htons((unsigned short)port);
    if (inet_pton(AF_INET, addr, &sa.sin_addr) != 1) {
        if (err) snprintf(err, err_size, "неверный адрес %s", addr);
        close(fd);
        return -1;
    }

    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        if (err) snprintf(err, err_size, "bind %s:%d: %s", addr, port, strerror(errno));
        close(fd);
        return -1;
    }
    if (listen(fd, 8) != 0) {
        if (err) snprintf(err, err_size, "listen: %s", strerror(errno));
        close(fd);
        return -1;
    }

    /* Закрывать при exec обязательно: иначе слушающий сокет достаётся
       по наследству всякому запущенному нами процессу. Однажды так
       вышло, что обновление породило цепочку sh -> opkg -> postinst ->
       новая служба, и та унаследовала сокет прежней: порт занят, свой
       bind падает с «Address in use», а соединения копятся в очереди
       сокета, с которого никто не принимает. */
    fcntl(fd, F_SETFD, FD_CLOEXEC);

    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    h->fd   = fd;
    h->port = port;
    str_copy(h->bind_addr, sizeof(h->bind_addr), addr);
    return 0;
}

void http_close(http_t *h)
{
    if (h && h->fd >= 0) {
        close(h->fd);
        h->fd = -1;
    }
}

void http_send(int fd, int code, const char *ctype, const char *body, size_t len)
{
    const char *reason = code == 200 ? "OK"
                       : code == 400 ? "Bad Request"
                       : code == 401 ? "Unauthorized"
                       : code == 404 ? "Not Found"
                       : code == 500 ? "Internal Server Error"
                       : "OK";

    char head[512];
    int  n = snprintf(head, sizeof(head),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Cache-Control: no-store\r\n"
        /* Управление роутером не должно открываться со сторонних
           страниц: без этого хватило бы одной вкладки в браузере. */
        "X-Content-Type-Options: nosniff\r\n"
        "X-Frame-Options: DENY\r\n"
        "Connection: close\r\n"
        "\r\n",
        code, reason, ctype ? ctype : "text/plain; charset=utf-8", len);

    if (n < 0 || (size_t)n >= sizeof(head)) return;

    if (write(fd, head, (size_t)n) != n) return;
    if (len && body) {
        size_t off = 0;
        while (off < len) {
            ssize_t k = write(fd, body + off, len - off);
            if (k <= 0) break;
            off += (size_t)k;
        }
    }
}

void http_send_with(int fd, int code, const char *ctype,
                    const char *extra1, const char *extra2,
                    const char *body, size_t len)
{
    char head[512];
    int  n = snprintf(head, sizeof(head),
                      "HTTP/1.1 %d %s\r\n"
                      "Content-Type: %s\r\n"
                      "Content-Length: %zu\r\n"
                      "Cache-Control: no-store\r\n"
                      "%s%s%s%s"
                      "Connection: close\r\n\r\n",
                      code, code == 303 ? "See Other" : "OK", ctype, len,
                      extra1 && *extra1 ? extra1 : "", extra1 && *extra1 ? "\r\n" : "",
                      extra2 && *extra2 ? extra2 : "", extra2 && *extra2 ? "\r\n" : "");
    if (n < 0 || (size_t)n >= sizeof(head)) return;

    size_t off = 0;
    while (off < (size_t)n) {
        ssize_t k = write(fd, head + off, (size_t)n - off);
        if (k <= 0) return;
        off += (size_t)k;
    }

    off = 0;
    while (len && body && off < len) {
        ssize_t k = write(fd, body + off, len - off);
        if (k <= 0) return;
        off += (size_t)k;
    }
}

void http_send_text(int fd, int code, const char *ctype, const char *body)
{
    http_send(fd, code, ctype, body, body ? strlen(body) : 0);
}

void http_send_gzip(int fd, const char *ctype,
                    const unsigned char *body, size_t len)
{
    char head[512];
    int  n = snprintf(head, sizeof(head),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: %s\r\n"
        "Content-Encoding: gzip\r\n"
        "Content-Length: %zu\r\n"
        "Cache-Control: no-store\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "X-Frame-Options: DENY\r\n"
        "Connection: close\r\n"
        "\r\n",
        ctype ? ctype : "text/html; charset=utf-8", len);

    if (n < 0 || (size_t)n >= sizeof(head)) return;
    if (write(fd, head, (size_t)n) != n) return;

    size_t off = 0;
    while (off < len) {
        ssize_t k = write(fd, body + off, len - off);
        if (k <= 0) break;
        off += (size_t)k;
    }
}

void http_poll(http_t *h,
               void (*handler)(const http_req_t *req, int fd, void *ctx),
               void *ctx)
{
    if (!h || h->fd < 0) return;

    /* По одному соединению за проход: демон должен вернуться в главный
       цикл к перехвату и сигналам, а не застревать на веб-интерфейсе. */
    for (int i = 0; i < 8; i++) {
        struct sockaddr_in from;
        socklen_t          fromlen = sizeof(from);
        int c = accept(h->fd, (struct sockaddr *)&from, &fromlen);
        if (c < 0) break;

        /* Снимаем неблокирующий режим явно. В BSD и macOS принятый сокет
           наследует его от слушающего, и тогда read возвращает «пока
           нечего» ещё до того, как запрос доедет: соединение закрывалось
           без ответа. В Linux наследования нет, поэтому на роутере это
           не проявилось бы вовсе. Ждать даём таймауту ниже. */
        fcntl(c, F_SETFD, FD_CLOEXEC);

        int cf = fcntl(c, F_GETFL, 0);
        if (cf != -1) fcntl(c, F_SETFL, cf & ~O_NONBLOCK);

        struct timeval tv = { 5, 0 };
        setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        /* Читаем, пока не приедет тело целиком. Одного read() мало:
           браузер шлёт заголовки и тело разными сегментами, и тогда
           запрос выглядит как пустой. По петле это незаметно, а через
           роутер сохранялся пустой файл — с ответом «сохранено». */
        static char buf[HTTP_BUF_BYTES];
        size_t      got  = 0;
        size_t      head = 0;
        long        clen = -1;
        int         full = 0;

        while (got < sizeof(buf) - 1) {
            ssize_t k = read(c, buf + got, sizeof(buf) - 1 - got);
            if (k <= 0) break;
            got += (size_t)k;

            if (!head) {
                size_t      skip = 0;
                const char *sep  = http_headers_end(buf, got, &skip);
                if (!sep) continue;
                head = (size_t)(sep - buf) + skip;
                clen = http_content_length(buf, (size_t)(sep - buf));
            }

            if (clen <= 0 || got - head >= (size_t)clen) { full = 1; break; }
        }

        /* Заявленное тело больше буфера: принять его целиком нельзя, а
           передать обрезок обработчику — значит записать обрезок в файл.
           Ровно это и происходило: проверка «пришло целиком» смотрела
           только на неотрицательную длину, а -2 проскакивал. */
        if (head && clen == -2) {
            http_send_text(c, 413, "text/plain; charset=utf-8",
                           "слишком большой запрос, ничего не изменено\n");
            h->rejected++;
            close(c);
            continue;
        }

        if (got > 0 && !full && head && clen > 0) {
            /* Тело оборвалось. Раньше здесь молча писался обрезок. */
            http_send_text(c, 400, "text/plain; charset=utf-8",
                           "запрос пришёл не целиком\n");
            h->rejected++;
            close(c);
            continue;
        }

        if (got > 0) {
            buf[got] = '\0';

            http_req_t req;
            int bad_req = http_parse_request(buf, got, &req);

            /* Адрес запрашивающего нужен проверке DNS: она отвечает на
               вопрос «спрашивает ли роутер именно это устройство». */
            if (!bad_req && fromlen >= (socklen_t)sizeof(struct sockaddr_in) &&
                from.sin_family == AF_INET)
                inet_ntop(AF_INET, &from.sin_addr, req.peer, sizeof(req.peer));

            if (bad_req) {
                http_send_text(c, 400, "text/plain; charset=utf-8",
                               "битый запрос\n");
                h->rejected++;
            } else if (h->token[0] && strcmp(h->token, req.token) != 0) {
                http_send_text(c, 401, "text/plain; charset=utf-8",
                               "нужен токен\n");
                h->rejected++;
            } else {
                h->served++;
                if (handler) handler(&req, c, ctx);
            }
        }

        close(c);
    }
}
