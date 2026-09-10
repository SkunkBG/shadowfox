#include "rci.h"
#include "log.h"
#include "util.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

void rci_init(rci_t *r)
{
    memset(r, 0, sizeof(*r));
    /* Только петля: RCI слушает локально, наружу его выпускать нельзя. */
    str_copy(r->host, sizeof(r->host), "127.0.0.1");
    r->port    = 79;
    r->timeout = 5;
}

int rci_parse_mark(const char *text, unsigned *mark)
{
    if (!text || !mark) return -1;

    while (*text == ' ' || *text == '"' || *text == '\n' || *text == '\r')
        text++;

    if (text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) text += 2;
    if (!isxdigit((unsigned char)*text)) return -1;

    char *end = NULL;
    unsigned long v = strtoul(text, &end, 16);
    if (!end || end == text) return -1;

    /* Хвост допустим только из кавычки и пробельных символов. */
    while (*end) {
        if (*end != '"' && !isspace((unsigned char)*end)) return -1;
        end++;
    }

    *mark = (unsigned)v;
    return 0;
}

static int connect_rci(const rci_t *r)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct timeval tv = { r->timeout > 0 ? r->timeout : 5, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port   = htons((unsigned short)r->port);
    if (inet_pton(AF_INET, r->host, &sa.sin_addr) != 1) { close(fd); return -1; }

    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int rci_request(const rci_t *r, const char *method, const char *path,
                const char *body, char *out, unsigned out_size)
{
    if (!r || !method || !path) return -1;
    if (out && out_size) out[0] = '\0';

    int fd = connect_rci(r);
    if (fd < 0) return -1;

    /* Заголовки и тело — одной записью. Раздельная отправка законна, но
       порождает два пакета на каждый запрос и заставляет принимающую
       сторону читать дважды. */
    char req[RCI_BODY_MAX];
    int  n = snprintf(req, sizeof(req),
        "%s %s HTTP/1.0\r\n"
        "Host: %s\r\n"
        "Content-Type: application/json\r\n"
        "%s%s%s"
        "Content-Length: %zu\r\n"
        "\r\n"
        "%s",
        method, path, r->host,
        r->token[0] ? "Authorization: Token " : "",
        r->token[0] ? r->token : "",
        r->token[0] ? "\r\n" : "",
        body ? strlen(body) : (size_t)0,
        body ? body : "");

    if (n < 0 || (unsigned)n >= sizeof(req)) { close(fd); return -1; }

    ssize_t sent = 0;
    while (sent < n) {
        ssize_t k = write(fd, req + sent, (size_t)(n - sent));
        if (k <= 0) { close(fd); return -1; }
        sent += k;
    }

    char   resp[RCI_BODY_MAX];
    size_t got = 0;
    for (;;) {
        ssize_t k = read(fd, resp + got, sizeof(resp) - 1 - got);
        if (k <= 0) break;
        got += (size_t)k;
        if (got + 1 >= sizeof(resp)) break;
    }
    resp[got] = '\0';
    close(fd);

    if (got < 12 || strncmp(resp, "HTTP/1.", 7) != 0) return -1;

    int code = atoi(resp + 9);

    /* Тело начинается после пустой строки. */
    const char *sep = strstr(resp, "\r\n\r\n");
    size_t      skip = 4;
    if (!sep) { sep = strstr(resp, "\n\n"); skip = 2; }

    if (sep && out && out_size)
        str_copy(out, out_size, sep + skip);

    return code;
}

int rci_policy_mark(const rci_t *r, const char *policy, unsigned *mark)
{
    if (!r || !policy || !*policy || !mark) return -1;

    char path[256];
    snprintf(path, sizeof(path), "/rci/show/ip/policy/%s/mark", policy);

    char body[256];
    int  code = rci_request(r, "GET", path, NULL, body, sizeof(body));

    if (code != 200) {
        /* 404 — политики ещё нет. Это не сбой: её создадут и метка
           появится позже, поэтому отличаем от сетевой ошибки. */
        return (code == 404) ? -2 : -1;
    }

    return rci_parse_mark(body, mark);
}

int rci_policy_create(const rci_t *r, const char *policy)
{
    if (!r || !policy || !*policy) return -1;

    /* parse эквивалентен вводу `ip policy <имя>` в консоли роутера:
       существующую политику не трогает, отсутствующую создаёт пустой.
       Интерфейсы в неё администратор назначает сам через панель. */
    char body[512];
    snprintf(body, sizeof(body),
             "[{\"parse\":\"ip policy %s\"},"
             "{\"system\":{\"configuration\":{\"save\":true}}}]",
             policy);

    char out[512];
    int  code = rci_request(r, "POST", "/rci/", body, out, sizeof(out));

    return (code == 200) ? 0 : -1;
}

/* Строковое поле верхнего уровня из ответа RCI. Разбор грубый: ответ
   короткий и свой, тащить разборщик JSON ради двух полей незачем. */
static int rci_field(const char *text, const char *name, char *out, size_t out_size)
{
    char pat[64];
    int  n = snprintf(pat, sizeof(pat), "\"%s\":\"", name);
    if (n < 0 || (size_t)n >= sizeof(pat)) return 0;
    const char *p = strstr(text, pat);
    if (!p) return 0;
    p += n;
    size_t i = 0;
    while (*p && *p != '"' && i + 1 < out_size) {
        if (*p == '\\' && p[1]) p++;
        out[i++] = *p++;
    }
    out[i] = '\0';
    return i > 0;
}

int rci_device_info(const rci_t *r, char *model, size_t model_size,
                    char *osver, size_t osver_size)
{
    if (model && model_size) model[0] = '\0';
    if (osver && osver_size) osver[0] = '\0';
    char out[2048] = "";
    if (rci_request(r, "GET", "/rci/show/version", NULL, out, sizeof(out)) != 200)
        return -1;
    static const char *models[]   = { "description", "device", "model", NULL };
    static const char *versions[] = { "title", "release", "version", NULL };
    if (model)
        for (int i = 0; models[i] && !model[0]; i++) rci_field(out, models[i], model, model_size);
    if (osver)
        for (int i = 0; versions[i] && !osver[0]; i++) rci_field(out, versions[i], osver, osver_size);
    return 0;
}
