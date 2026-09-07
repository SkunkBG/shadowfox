/* Разбор HTTP-запросов и отказ слушать на всех интерфейсах. */
#include "http.h"
#include "shadowfox.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>

static int failures = 0;

#define CHECK(cond, ...)                                     \
    do {                                                     \
        if (!(cond)) {                                       \
            printf("  ПРОВАЛ %s:%d: ", __FILE__, __LINE__);  \
            printf(__VA_ARGS__);                             \
            printf("\n");                                    \
            failures++;                                      \
        }                                                    \
    } while (0)

static int parse(const char *text, http_req_t *r)
{
    return http_parse_request(text, strlen(text), r);
}

static void test_simple_get(void)
{
    http_req_t r;
    CHECK(parse("GET /api/status HTTP/1.1\r\nHost: x\r\n\r\n", &r) == 0,
          "запрос разобран");
    CHECK(!strcmp(r.method, "GET"), "метод: %s", r.method);
    CHECK(!strcmp(r.path, "/api/status"), "путь: %s", r.path);
    CHECK(r.query[0] == '\0', "строки запроса нет");
}

static void test_query(void)
{
    http_req_t r;
    CHECK(parse("GET /api/set?group=media&value=7 HTTP/1.1\r\n\r\n", &r) == 0,
          "разобран");
    CHECK(!strcmp(r.path, "/api/set"), "путь без строки запроса: %s", r.path);

    char v[64];
    CHECK(http_query_get(&r, "group", v, sizeof(v)) == 1 && !strcmp(v, "media"),
          "параметр group: %s", v);
    CHECK(http_query_get(&r, "value", v, sizeof(v)) == 1 && !strcmp(v, "7"),
          "параметр value");
    CHECK(http_query_get(&r, "нет", v, sizeof(v)) == 0, "отсутствующий параметр");
    /* Имя сравнивается целиком: "rou" не должно найтись внутри "group". */
    CHECK(http_query_get(&r, "rou", v, sizeof(v)) == 0, "не подстрока");
}

static void test_body(void)
{
    http_req_t r;
    const char *req =
        "POST /api/domains HTTP/1.1\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: 13\r\n"
        "\r\n"
        "{\"a\":\"тест\"}";

    CHECK(parse(req, &r) == 0, "запрос с телом разобран");
    CHECK(!strcmp(r.method, "POST"), "метод POST");
    CHECK(r.body != NULL, "тело найдено");
    CHECK(r.body && strstr(r.body, "тест") != NULL, "содержимое тела");
}

/* Куки не различают порт: браузер шлёт нам и куки веб-интерфейса
   роутера с того же адреса. Заголовок от этого длинный, и наша метка
   сессии оказывается в конце — копия в буфер её обрезала, а вход
   слетал после захода на страницу роутера. */
static void test_long_cookie(void)
{
    http_req_t r;

    static char req[4096];
    int n = snprintf(req, sizeof(req),
                     "GET /data HTTP/1.1\r\nHost: t\r\nCookie: ");

    /* Набиваем чужими куками так, чтобы наша ушла далеко за 256 байт. */
    for (int i = 0; i < 12; i++)
        n += snprintf(req + n, sizeof(req) - (size_t)n,
                      "ndm_session_%02d=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; ", i);

    n += snprintf(req + n, sizeof(req) - (size_t)n,
                  "sfsession=deadbeef0123456789\r\n\r\n");

    CHECK(parse(req, &r) == 0, "запрос разобран");
    CHECK(r.cookie != NULL, "заголовок Cookie найден");
    CHECK(r.cookie_len > 400, "и он длинный: %zu", r.cookie_len);

    /* Ищем нашу метку так же, как это делает обработчик. */
    char        want[] = "sfsession=";
    const char *found  = NULL;
    for (const char *p = r.cookie; p + sizeof(want) - 1 < r.cookie + r.cookie_len; p++)
        if (!strncmp(p, want, sizeof(want) - 1)) { found = p + sizeof(want) - 1; break; }

    CHECK(found != NULL, "метка сессии видна целиком");
    CHECK(found && !strncmp(found, "deadbeef0123456789", 18),
          "и значение не обрезано");
}

/* Обработчик для проверки: смотрит флаги дескриптора соединения. */
static int g_accepted_cloexec;

static void reply_cloexec(const http_req_t *r, int fd, void *ctx)
{
    (void)r; (void)ctx;
    int f = fcntl(fd, F_GETFD, 0);
    g_accepted_cloexec = (f != -1 && (f & FD_CLOEXEC)) ? 1 : 0;
    http_send_text(fd, 200, "text/plain", "ok\n");
}

/* Слушающий сокет не должен доставаться запущенным нами процессам.
   Один раз так и вышло: обновление породило цепочку sh -> opkg ->
   postinst -> новая служба, и та унаследовала сокет прежней. Порт занят,
   свой bind падает с «Address in use», а соединения копятся в очереди
   сокета, с которого никто не принимает. */
static void test_listener_not_inherited(void)
{
    http_t h;
    char   err[128];

    http_init(&h);
    CHECK(http_open(&h, "127.0.0.1", 0, err, sizeof(err)) == 0,
          "сервер поднят: %s", err);

    int flags = fcntl(http_fd(&h), F_GETFD, 0);
    CHECK(flags != -1 && (flags & FD_CLOEXEC),
          "на слушающем сокете стоит FD_CLOEXEC");

    /* И на принятом тоже: он живёт недолго, но утечь успевает. */
    struct sockaddr_in sa;
    socklen_t sl = sizeof(sa);
    getsockname(http_fd(&h), (struct sockaddr *)&sa, &sl);

    int c = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in to;
    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_port   = sa.sin_port;
    inet_pton(AF_INET, "127.0.0.1", &to.sin_addr);

    if (connect(c, (struct sockaddr *)&to, sizeof(to)) == 0) {
        const char *req = "GET /x HTTP/1.1\r\nHost: t\r\n\r\n";
        if (write(c, req, strlen(req)) > 0) {
            /* Обработчик увидит дескриптор принятого соединения. */
            http_poll(&h, reply_cloexec, NULL);
            CHECK(g_accepted_cloexec == 1, "на принятом сокете тоже FD_CLOEXEC");
        }
    }
    close(c);

    http_close(&h);
}

static void test_token(void)
{
    http_req_t r;
    CHECK(parse("GET / HTTP/1.1\r\nAuthorization: Bearer СЕКРЕТ\r\n\r\n", &r) == 0,
          "разобран");
    CHECK(!strcmp(r.token, "СЕКРЕТ"), "токен без схемы: %s", r.token);

    /* Без схемы тоже принимаем: заголовок пишут по-разному. */
    CHECK(parse("GET / HTTP/1.1\r\nauthorization: ПРОСТО\r\n\r\n", &r) == 0,
          "разобран в нижнем регистре");
    CHECK(!strcmp(r.token, "ПРОСТО"), "токен без схемы: %s", r.token);

    CHECK(parse("GET / HTTP/1.1\r\n\r\n", &r) == 0, "без заголовка");
    CHECK(r.token[0] == '\0', "токен пуст");
}

static void test_garbage(void)
{
    http_req_t r;

    CHECK(parse("", &r) == -1, "пустой запрос");
    CHECK(parse("GET", &r) == -1, "без пути");
    CHECK(parse("GET  HTTP/1.1\r\n\r\n", &r) == -1, "пустой путь");
    CHECK(http_parse_request(NULL, 10, &r) == -1, "NULL");

    /* Слишком длинный путь не должен переполнять буфер. */
    char big[HTTP_PATH_MAX + 64];
    memset(big, 'a', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';

    char req[HTTP_PATH_MAX + 128];
    snprintf(req, sizeof(req), "GET /%s HTTP/1.1\r\n\r\n", big);
    CHECK(parse(req, &r) == -1, "длинный путь отвергнут");
}

static void test_refuses_all_interfaces(void)
{
    http_t h;
    char   err[128];

    http_init(&h);
    /* neofit держал управление роутером на всех интерфейсах без
       авторизации. Повторять это нельзя даже по недосмотру. */
    CHECK(http_open(&h, "0.0.0.0", 18080, err, sizeof(err)) == -1,
          "0.0.0.0 отвергнут");
    CHECK(strstr(err, "0.0.0.0") != NULL, "причина названа: %s", err);

    CHECK(http_open(&h, "*", 18080, err, sizeof(err)) == -1, "звёздочка тоже");
    CHECK(http_open(&h, "", 18080, err, sizeof(err)) == -1, "пустой адрес");

    CHECK(http_open(&h, "127.0.0.1", 0, err, sizeof(err)) == 0,
          "петля принимается: %s", err);
    CHECK(http_fd(&h) >= 0, "сокет открыт");
    http_close(&h);
    CHECK(http_fd(&h) == -1, "закрытие");
}

static void reply(const http_req_t *r, int fd, void *ctx)
{
    (void)r; (void)ctx;
    http_send_text(fd, 200, "text/plain; charset=utf-8", "ответ\n");
}

static int g_port;

/* Клиент подключается, выжидает и только потом шлёт запрос. */
static void *late_client(void *arg)
{
    (void)arg;

    int c = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port   = htons((unsigned short)g_port);
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);

    if (connect(c, (struct sockaddr *)&sa, sizeof(sa)) != 0) { close(c); return NULL; }

    struct timespec ts = { 0, 150 * 1000 * 1000 };
    nanosleep(&ts, NULL);

    const char *req = "GET /x HTTP/1.1\r\nHost: t\r\n\r\n";
    if (write(c, req, strlen(req)) < 0) { close(c); return NULL; }

    static char buf[512];
    ssize_t n = read(c, buf, sizeof(buf) - 1);
    if (n > 0) buf[n] = '\0'; else buf[0] = '\0';
    close(c);

    return strstr(buf, "200 OK") ? (void *)1 : NULL;
}

/* Тело отдельным сегментом — так и шлёт браузер. Отвечающий обработчик
   пишет, сколько тела доехало, чтобы проверка увидела именно это. */
static char g_body[4096];
static size_t g_body_len;
static long   g_declared;

static void body_reply(const http_req_t *r, int fd, void *ctx)
{
    (void)ctx;
    g_body_len = r->body_len;
    g_declared = r->declared_len;
    if (r->body && r->body_len < sizeof(g_body))
        memcpy(g_body, r->body, r->body_len);
    http_send_text(fd, 200, "text/plain", "ok\n");
}

static int   g_split_hold;   /* сколько байт тела не досылать */
static char  g_payload[900];

static void *split_client(void *arg)
{
    (void)arg;

    int c = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port   = htons((unsigned short)g_port);
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    if (connect(c, (struct sockaddr *)&sa, sizeof(sa)) != 0) { close(c); return NULL; }

    size_t len = strlen(g_payload);
    char   head[256];
    int    hn = snprintf(head, sizeof(head),
                         "POST /save?what=domains HTTP/1.1\r\nHost: t\r\n"
                         "Content-Length: %zu\r\n\r\n", len);
    if (write(c, head, (size_t)hn) < 0) { close(c); return NULL; }

    /* Пауза между заголовками и телом — суть проверки. */
    struct timespec ts = { 0, 120 * 1000 * 1000 };
    nanosleep(&ts, NULL);

    size_t send = len - (size_t)g_split_hold;
    if (write(c, g_payload, send) < 0) { close(c); return NULL; }
    shutdown(c, SHUT_WR);

    static char buf[512];
    ssize_t n = read(c, buf, sizeof(buf) - 1);
    if (n > 0) buf[n] = '\0'; else buf[0] = '\0';
    close(c);

    return strstr(buf, "200 OK") ? (void *)1 : (void *)2;
}

/* Заявленная длина больше буфера. Раньше такой запрос принимался как
   «пришёл целиком» после первого read, и обрезок уезжал в файл. */
static int g_over_called;

static void over_reply(const http_req_t *r, int fd, void *ctx)
{
    (void)r; (void)ctx;
    g_over_called++;
    http_send_text(fd, 200, "text/plain", "ok\n");
}

static void *over_client(void *arg)
{
    (void)arg;

    int c = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port   = htons((unsigned short)g_port);
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    if (connect(c, (struct sockaddr *)&sa, sizeof(sa)) != 0) { close(c); return NULL; }

    const char *req =
        "POST /save?what=domains HTTP/1.1\r\nHost: t\r\n"
        "Content-Length: 9000000\r\n\r\nначало списка\n";
    if (write(c, req, strlen(req)) < 0) { close(c); return NULL; }
    shutdown(c, SHUT_WR);

    static char buf[512];
    ssize_t n = read(c, buf, sizeof(buf) - 1);
    if (n > 0) buf[n] = '\0'; else buf[0] = '\0';
    close(c);

    return strstr(buf, "413") ? (void *)1 : (void *)2;
}

static void test_oversized_body(void)
{
    g_over_called = 0;

    http_t h;
    char   err[128];
    http_init(&h);
    CHECK(http_open(&h, "127.0.0.1", 0, err, sizeof(err)) == 0, "сервер: %s", err);

    struct sockaddr_in sa;
    socklen_t sl = sizeof(sa);
    getsockname(http_fd(&h), (struct sockaddr *)&sa, &sl);
    g_port = ntohs(sa.sin_port);

    pthread_t th;
    pthread_create(&th, NULL, over_client, NULL);

    for (int i = 0; i < 40 && !g_over_called; i++) {
        struct timespec ts = { 0, 50 * 1000 * 1000 };
        nanosleep(&ts, NULL);
        http_poll(&h, over_reply, NULL);
    }

    void *res = NULL;
    pthread_join(th, &res);

    CHECK(res == (void *)1, "ожидался ответ 413");
    CHECK(g_over_called == 0, "обработчик не должен вызываться: %d", g_over_called);
    CHECK(h.rejected == 1, "отказ засчитан: %lu", h.rejected);

    http_close(&h);
}

static void *run_split(int hold)
{
    g_split_hold = hold;
    g_body_len   = 0;
    g_declared   = -1;
    memset(g_body, 0, sizeof(g_body));

    http_t h;
    char   err[128];
    http_init(&h);
    CHECK(http_open(&h, "127.0.0.1", 0, err, sizeof(err)) == 0, "сервер: %s", err);

    struct sockaddr_in sa;
    socklen_t sl = sizeof(sa);
    getsockname(http_fd(&h), (struct sockaddr *)&sa, &sl);
    g_port = ntohs(sa.sin_port);

    pthread_t th;
    pthread_create(&th, NULL, split_client, NULL);

    void *res = NULL;
    for (int i = 0; i < 60; i++) {
        http_poll(&h, body_reply, NULL);
        struct timespec ts = { 0, 20 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
    pthread_join(th, &res);
    http_close(&h);
    return res;
}

/* Тело, приехавшее вторым сегментом, обязано дойти целиком. Раньше
   читался один read(): заголовки успевали, тело нет, и веб-страница
   молча перезаписывала список доменов пустотой. */
static void test_body_second_segment(void)
{
    for (size_t i = 0; i + 1 < sizeof(g_payload); i++)
        g_payload[i] = (char)('a' + (i % 26));
    g_payload[sizeof(g_payload) - 1] = '\0';

    void *res = run_split(0);
    CHECK(res == (void *)1, "запрос обслужен");
    CHECK(g_body_len == strlen(g_payload),
          "тело целиком: %zu из %zu", g_body_len, strlen(g_payload));
    CHECK(g_declared == (long)strlen(g_payload),
          "Content-Length разобран: %ld", g_declared);
    CHECK(memcmp(g_body, g_payload, g_body_len) == 0, "тело не побилось");
}

/* Оборванное тело — отказ, а не обрезок: списки перезаписываются целиком. */
static void test_body_truncated(void)
{
    void *res = run_split(300);
    CHECK(res == (void *)2, "оборванное тело отклонено");
    CHECK(g_body_len == 0, "обработчик не вызван, тела нет: %zu", g_body_len);
}

/* Разбор Content-Length отдельно: испорченное значение принимать нельзя. */
static void test_content_length(void)
{
    const char *a = "POST / HTTP/1.1\r\nContent-Length: 42\r\n";
    CHECK(http_content_length(a, strlen(a)) == 42, "длина 42");

    const char *b = "POST / HTTP/1.1\r\ncontent-length:  7\r\n";
    CHECK(http_content_length(b, strlen(b)) == 7, "регистр и пробелы");

    const char *c = "POST / HTTP/1.1\r\nHost: x\r\n";
    CHECK(http_content_length(c, strlen(c)) == -1, "заголовка нет");

    const char *d = "POST / HTTP/1.1\r\nContent-Length: abc\r\n";
    CHECK(http_content_length(d, strlen(d)) == -2, "мусор отвергнут");

    /* Подделка вида X-Content-Length не должна сойти за настоящий. */
    const char *e = "POST / HTTP/1.1\r\nX-Content-Length: 9\r\n";
    CHECK(http_content_length(e, strlen(e)) == -1, "чужой заголовок не считается");
}

/* Запрос, пришедший позже соединения, обязан быть обслужен.
   В BSD принятый сокет наследует неблокирующий режим от слушающего, и
   без явного снятия сервер закрывал такие соединения, не ответив. */
static void test_late_request(void)
{
    http_t h;
    char   err[128];

    http_init(&h);
    CHECK(http_open(&h, "127.0.0.1", 0, err, sizeof(err)) == 0,
          "сервер поднят: %s", err);

    struct sockaddr_in sa;
    socklen_t sl = sizeof(sa);
    getsockname(http_fd(&h), (struct sockaddr *)&sa, &sl);
    g_port = ntohs(sa.sin_port);

    pthread_t th;
    pthread_create(&th, NULL, late_client, NULL);

    /* Крутим приём, как это делает главный цикл демона. */
    void *res = NULL;
    for (int i = 0; i < 40; i++) {
        http_poll(&h, reply, NULL);
        struct timespec ts = { 0, 25 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
    pthread_join(th, &res);

    CHECK(res != NULL, "запоздавший запрос обслужен");
    CHECK(h.served >= 1, "соединение засчитано, обслужено %lu", h.served);

    http_close(&h);
}

/* Origin и Host нужны защите от чужого POST; искать их надо только в
   начале строки, иначе слово внутри значения сойдёт за заголовок. */
static void test_origin_host(void)
{
    http_req_t r;
    const char *req =
        "POST /save HTTP/1.1\r\n"
        "Host: 192.168.1.1:8090\r\n"
        "X-Note: Origin: http://evil.example\r\n"
        "Origin: http://192.168.1.1:8090\r\n\r\n";
    CHECK(parse(req, &r) == 0, "разобран");
    CHECK(strcmp(r.host, "192.168.1.1:8090") == 0, "host: «%s»", r.host);
    CHECK(strcmp(r.origin, "http://192.168.1.1:8090") == 0, "origin: «%s»", r.origin);

    const char *bare = "GET / HTTP/1.1\r\nHost: t\r\n\r\n";
    CHECK(parse(bare, &r) == 0, "разобран");
    CHECK(r.origin[0] == '\0', "без Origin поле пустое");
}

int main(void)
{
    printf("check_http " VERSION "\n");

    test_simple_get();
    test_query();
    test_body();
    test_long_cookie();
    test_listener_not_inherited();
    test_token();
    test_garbage();
    test_refuses_all_interfaces();
    test_late_request();
    test_content_length();
    test_body_second_segment();
    test_body_truncated();
    test_oversized_body();
    test_origin_host();

    if (failures) {
        printf("ПРОВАЛЕНО проверок: %d\n", failures);
        return 1;
    }
    printf("все проверки пройдены\n");
    return 0;
}
