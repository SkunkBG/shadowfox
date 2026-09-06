/* Разбор HTTP-запросов и отказ слушать на всех интерфейсах. */
#include "http.h"
#include "shadowfox.h"

#include <stdio.h>
#include <string.h>

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

int main(void)
{
    printf("check_http " VERSION "\n");

    test_simple_get();
    test_query();
    test_body();
    test_token();
    test_garbage();
    test_refuses_all_interfaces();

    if (failures) {
        printf("ПРОВАЛЕНО проверок: %d\n", failures);
        return 1;
    }
    printf("все проверки пройдены\n");
    return 0;
}
