#include "probe.h"
#include "shadowfox.h"

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

static int failures;

#define CHECK(cond, msg) do { \
    if (!(cond)) { printf("  ПРОВАЛ %s:%d: %s\n", __FILE__, __LINE__, msg); failures++; } \
} while (0)

/* Подставной SOCKS-сервер в том же процессе: проверка неблокирующая,
   поэтому её можно крутить между чтениями с серверной стороны. */
static int listen_local(int *port)
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) != 0) return -1;
    listen(s, 4);
    socklen_t sl = sizeof(sa);
    getsockname(s, (struct sockaddr *)&sa, &sl);
    *port = ntohs(sa.sin_port);
    return s;
}

/* Крутит проверку, пока она не дойдёт до состояния или не завершится. */
static int drive_until(probe_t *p, probe_state_t st, long now)
{
    for (int i = 0; i < 2000; i++) {
        if (probe_poll(p, now)) return 1;
        if (p->state == st) return 0;
        usleep(1000);
    }
    return -1;
}

/* Читает с серверной стороны ровно n байт. */
static int read_n(int c, unsigned char *buf, size_t n)
{
    size_t got = 0;
    while (got < n) {
        ssize_t r = recv(c, buf + got, n - got, 0);
        if (r <= 0) return -1;
        got += (size_t)r;
    }
    return 0;
}

static int read_until_blank(int c)
{
    char buf[1024];
    size_t got = 0;
    while (got < sizeof(buf) - 1) {
        ssize_t r = recv(c, buf + got, 1, 0);
        if (r <= 0) return -1;
        got += (size_t)r;
        buf[got] = '\0';
        if (strstr(buf, "\r\n\r\n")) {
            return strstr(buf, "GET /generate_204 HTTP/1.1\r\nHost: example.test\r\n") ? 0 : -2;
        }
    }
    return -1;
}

/* Проводит проверку до фазы HTTP и возвращает клиентский сокет сервера. */
static int to_http(probe_t *p, int srv, int port, long now)
{
    CHECK(probe_start(p, "127.0.0.1", port, "http://example.test/generate_204", now) == 0,
          "проверка стартует");
    int c = accept(srv, NULL, NULL);
    CHECK(c >= 0, "сервер принял соединение");

    CHECK(drive_until(p, PROBE_GREET, now) == 0, "дошли до приветствия");
    unsigned char b[300];
    CHECK(read_n(c, b, 3) == 0 && b[0] == 5 && b[1] == 1 && b[2] == 0, "приветствие без пароля");
    send(c, "\x05\x00", 2, 0);

    CHECK(drive_until(p, PROBE_REQUEST, now) == 0, "дошли до CONNECT");
    CHECK(read_n(c, b, 5) == 0 && b[0] == 5 && b[1] == 1 && b[3] == 3 && b[4] == 12,
          "CONNECT к имени длиной 12");
    CHECK(read_n(c, b, 14) == 0 && memcmp(b, "example.test", 12) == 0 &&
          b[12] == 0 && b[13] == 80, "имя и порт 80");
    return c;
}

static void test_ok(void)
{
    int port, srv = listen_local(&port);
    probe_t p; probe_init(&p);
    int c = to_http(&p, srv, port, 100);

    CHECK(probe_fd(&p) == p.fd, "в ожидании ответа дескриптор отдаётся циклу");
    send(c, "\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00", 10, 0);
    CHECK(drive_until(&p, PROBE_HTTP, 100) == 0, "дошли до HTTP");
    CHECK(read_until_blank(c) == 0, "GET с нужным путём и Host");
    send(c, "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n", 45, 0);
    CHECK(drive_until(&p, PROBE_DONE, 100) == 1, "завершилась");
    CHECK(p.ok == 1, "туннель отвечает");
    CHECK(p.ms >= 0 && p.ms < 5000, "задержка измерена");
    CHECK(p.fd < 0, "сокет закрыт");
    CHECK(probe_fd(&p) == -1, "после завершения дескриптора нет");
    close(c); close(srv);
}

static void test_http_error(void)
{
    int port, srv = listen_local(&port);
    probe_t p; probe_init(&p);
    int c = to_http(&p, srv, port, 100);
    send(c, "\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00", 10, 0);
    CHECK(drive_until(&p, PROBE_HTTP, 100) == 0, "дошли до HTTP");
    read_until_blank(c);
    send(c, "HTTP/1.1 503 Service Unavailable\r\n\r\n", 36, 0);
    CHECK(drive_until(&p, PROBE_DONE, 100) == 1, "завершилась");
    CHECK(p.ok == 0 && strcmp(p.why, "ответ HTTP 503") == 0, "код ответа в причине");
    close(c); close(srv);
}

static void test_closed_without_reply(void)
{
    /* Главный признак мёртвого сервера: ядро соглашается на CONNECT и
       потом закрывает соединение, не прислав ни байта. */
    int port, srv = listen_local(&port);
    probe_t p; probe_init(&p);
    int c = to_http(&p, srv, port, 100);
    send(c, "\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00", 10, 0);
    CHECK(drive_until(&p, PROBE_HTTP, 100) == 0, "дошли до HTTP");
    read_until_blank(c);
    close(c);
    CHECK(drive_until(&p, PROBE_DONE, 100) == 1, "завершилась");
    CHECK(p.ok == 0 && strstr(p.why, "без ответа") != NULL, "закрыто без ответа");
    close(srv);
}

static void test_socks_refused(void)
{
    int port, srv = listen_local(&port);
    probe_t p; probe_init(&p);
    int c = to_http(&p, srv, port, 100);
    send(c, "\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00", 10, 0);
    CHECK(drive_until(&p, PROBE_DONE, 100) == 1, "завершилась");
    CHECK(p.ok == 0 && strstr(p.why, "соединение отклонено") != NULL, "код SOCKS расшифрован");
    close(c); close(srv);
}

static void test_greeting_rejected(void)
{
    int port, srv = listen_local(&port);
    probe_t p; probe_init(&p);
    CHECK(probe_start(&p, "127.0.0.1", port, "http://example.test/generate_204", 100) == 0, "старт");
    int c = accept(srv, NULL, NULL);
    CHECK(drive_until(&p, PROBE_GREET, 100) == 0, "приветствие");
    unsigned char b[3]; read_n(c, b, 3);
    send(c, "\x05\xff", 2, 0);
    CHECK(drive_until(&p, PROBE_DONE, 100) == 1, "завершилась");
    CHECK(p.ok == 0 && strstr(p.why, "отвергло приветствие") != NULL, "приветствие отвергнуто");
    close(c); close(srv);
}

static void test_timeout(void)
{
    int port, srv = listen_local(&port);
    probe_t p; probe_init(&p);
    CHECK(probe_start(&p, "127.0.0.1", port, "http://example.test/generate_204", 100) == 0, "старт");
    int c = accept(srv, NULL, NULL);
    CHECK(drive_until(&p, PROBE_GREET, 100) == 0, "приветствие послано");
    CHECK(probe_poll(&p, 100 + PROBE_TIMEOUT - 1) == 0, "до срока ждём");
    CHECK(probe_poll(&p, 100 + PROBE_TIMEOUT) == 1, "по сроку завершена");
    CHECK(p.ok == 0 && strstr(p.why, "не ответило") != NULL, "причина — срок");
    close(c); close(srv);
}

static void test_refused(void)
{
    int port, srv = listen_local(&port);
    close(srv);   /* порт освободился: соединение отвергнет ядро ОС */
    probe_t p; probe_init(&p);
    int r = probe_start(&p, "127.0.0.1", port, "http://example.test/generate_204", 100);
    if (r == 0) CHECK(drive_until(&p, PROBE_DONE, 100) == 1, "отказ доходит до завершения");
    CHECK(p.ok == 0 && strstr(p.why, "нет связи с ядром") != NULL, "отказ в соединении с ядром");
    CHECK(p.fd < 0, "сокет закрыт после отказа");
}

static void test_parse_url(void)
{
    char host[PROBE_HOST_MAX], path[PROBE_PATH_MAX];
    int  port;
    CHECK(probe_parse_url("http://www.gstatic.com/generate_204", host, sizeof(host), &port,
                          path, sizeof(path)) == 0, "обычный адрес");
    CHECK(strcmp(host, "www.gstatic.com") == 0 && port == 80 &&
          strcmp(path, "/generate_204") == 0, "разобран");
    CHECK(probe_parse_url("http://h:8080", host, sizeof(host), &port, path, sizeof(path)) == 0 &&
          port == 8080 && strcmp(path, "/") == 0, "порт и пустой путь");
    CHECK(probe_parse_url("https://a/b", host, sizeof(host), &port, path, sizeof(path)) != 0,
          "https не берём");
    CHECK(probe_parse_url("http://a b/c", host, sizeof(host), &port, path, sizeof(path)) != 0,
          "пробел в имени");
    CHECK(probe_parse_url("http://a/c d", host, sizeof(host), &port, path, sizeof(path)) != 0,
          "пробел в пути");
    CHECK(probe_parse_url("http://a:0/", host, sizeof(host), &port, path, sizeof(path)) != 0,
          "порт 0");
    CHECK(probe_parse_url("http:///x", host, sizeof(host), &port, path, sizeof(path)) != 0,
          "без имени");
}

int main(void)
{
    printf("check_probe " VERSION "\n");
    signal(SIGPIPE, SIG_IGN);

    test_parse_url();
    test_ok();
    test_http_error();
    test_closed_without_reply();
    test_socks_refused();
    test_greeting_rejected();
    test_timeout();
    test_refused();

    if (failures) {
        printf("ПРОВАЛЕНО проверок: %d\n", failures);
        return 1;
    }
    printf("все проверки пройдены\n");
    return 0;
}
