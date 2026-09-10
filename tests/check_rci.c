/* Клиент RCI. Настоящего роутера тут нет, поэтому поднимаем крошечный
   HTTP-сервер прямо в тесте и отвечаем ему тем же, что отвечает Keenetic. */
#include "rci.h"
#include "shadowfox.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
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

static int         g_listen = -1;
static int         g_port   = 0;
static const char *g_reply  = NULL;
static char        g_seen[2048];

static void *serve_one(void *arg)
{
    (void)arg;
    int c = accept(g_listen, NULL, NULL);
    if (c < 0) return NULL;

    ssize_t n = read(c, g_seen, sizeof(g_seen) - 1);
    if (n > 0) g_seen[n] = '\0';

    if (g_reply) {
        size_t len = strlen(g_reply);
        if (write(c, g_reply, len) != (ssize_t)len) { /* клиент ушёл */ }
    }
    close(c);
    return NULL;
}

/* Готовит одноразовый ответ и возвращает клиента, настроенного на него. */
static void arm(rci_t *r, const char *reply, pthread_t *th)
{
    g_reply    = reply;
    g_seen[0]  = '\0';

    rci_init(r);
    r->port    = g_port;
    r->timeout = 3;

    pthread_create(th, NULL, serve_one, NULL);
}

static void test_parse_mark(void)
{
    unsigned m = 0;

    /* Ровно то, что отдаёт роутер: в кавычках и без префикса. */
    CHECK(rci_parse_mark("\"ffffaaa\"", &m) == 0 && m == 0xffffaaa,
          "метка из ответа роутера: %x", m);
    CHECK(rci_parse_mark("\"0xffffaaa\"\n", &m) == 0 && m == 0xffffaaa,
          "префикс 0x тоже принимается");
    CHECK(rci_parse_mark("  \"3001\"  ", &m) == 0 && m == 0x3001,
          "пробелы вокруг");

    CHECK(rci_parse_mark("", &m) == -1, "пустая строка");
    CHECK(rci_parse_mark("\"\"", &m) == -1, "пустое значение");
    CHECK(rci_parse_mark("не метка", &m) == -1, "мусор");
    CHECK(rci_parse_mark("\"ffff\" лишнее", &m) == -1, "мусор в хвосте");
    CHECK(rci_parse_mark(NULL, &m) == -1, "NULL");
}

static void test_get_mark(void)
{
    rci_t     r;
    pthread_t th;
    arm(&r, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            "\r\n\"ffffaaa\"", &th);

    unsigned mark = 0;
    int rc = rci_policy_mark(&r, "HydraRoute", &mark);
    pthread_join(th, NULL);

    CHECK(rc == 0, "метка получена, код %d", rc);
    CHECK(mark == 0xffffaaa, "значение метки: %x", mark);

    /* Путь должен быть именно тот, что понимает роутер. */
    CHECK(strstr(g_seen, "GET /rci/show/ip/policy/HydraRoute/mark") != NULL,
          "запрошен верный путь:\n%s", g_seen);
    CHECK(strstr(g_seen, "Host: 127.0.0.1") != NULL, "заголовок Host");
}

static void test_missing_policy(void)
{
    rci_t     r;
    pthread_t th;
    arm(&r, "HTTP/1.1 404 Not Found\r\n\r\n", &th);

    unsigned mark = 0;
    int rc = rci_policy_mark(&r, "НетТакой", &mark);
    pthread_join(th, NULL);

    /* Отсутствие политики — не сбой связи: её создадут, и метка
       появится позже. Различать эти случаи обязательно. */
    CHECK(rc == -2, "отсутствие политики отличается от ошибки, получено %d", rc);
}

static void test_create_policy(void)
{
    rci_t     r;
    pthread_t th;
    arm(&r, "HTTP/1.1 200 OK\r\n\r\n[]", &th);

    int rc = rci_policy_create(&r, "ShadowFox");
    pthread_join(th, NULL);

    CHECK(rc == 0, "политика создана");
    CHECK(strstr(g_seen, "POST /rci/") != NULL, "метод и путь");
    CHECK(strstr(g_seen, "\"parse\":\"ip policy ShadowFox\"") != NULL,
          "команда создания:\n%s", g_seen);
    /* Без сохранения конфигурации политика исчезнет после перезагрузки. */
    CHECK(strstr(g_seen, "\"save\":true") != NULL, "конфигурация сохраняется");
    CHECK(strstr(g_seen, "Content-Length:") != NULL, "длина тела указана");
}

static void test_no_server(void)
{
    rci_t r;
    rci_init(&r);
    r.port    = 1;      /* туда никто не слушает */
    r.timeout = 1;

    unsigned mark = 0;
    CHECK(rci_policy_mark(&r, "X", &mark) == -1, "недоступный RCI даёт ошибку");

    char out[64];
    CHECK(rci_request(&r, "GET", "/rci/", NULL, out, sizeof(out)) == -1,
          "запрос без сервера не падает, а возвращает ошибку");
}

static void test_field(void)
{
    const char *pretty =
        "{\n  \"release\": \"5.01.C.3.0-1\",\n  \"title\": \"5.1.3\",\n"
        "  \"ndm\": {\n    \"exact\": \"0-b73c\"\n  },\n"
        "  \"description\": \"Keenetic Ultra\",\n  \"model\": \"Ultra (KN-1811)\"\n}";
    char v[64];
    CHECK(rci_field(pretty, "title", v, sizeof(v)) && !strcmp(v, "5.1.3"), "title с пробелом: [%s]", v);
    CHECK(rci_field(pretty, "description", v, sizeof(v)) && !strcmp(v, "Keenetic Ultra"), "description: [%s]", v);
    CHECK(rci_field("{\"title\":\"4.2.6\"}", "title", v, sizeof(v)) && !strcmp(v, "4.2.6"), "без пробелов");
    CHECK(!rci_field(pretty, "nothere", v, sizeof(v)), "нет ключа");
    CHECK(!rci_field("{\"ndm\": {\"exact\": 1}}", "exact", v, sizeof(v)), "не строка — не берём");
}

int main(void)
{
    test_field();
    printf("check_rci " VERSION "\n");

    g_listen = socket(AF_INET, SOCK_STREAM, 0);
    int yes = 1;
    setsockopt(g_listen, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family      = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port        = 0;                    /* пусть система выберет */

    if (bind(g_listen, (struct sockaddr *)&sa, sizeof(sa)) != 0 ||
        listen(g_listen, 4) != 0) {
        printf("не поднять тестовый сервер\n");
        return 1;
    }

    socklen_t sl = sizeof(sa);
    getsockname(g_listen, (struct sockaddr *)&sa, &sl);
    g_port = ntohs(sa.sin_port);

    test_parse_mark();
    test_get_mark();
    test_missing_policy();
    test_create_policy();
    test_no_server();

    close(g_listen);

    if (failures) {
        printf("ПРОВАЛЕНО проверок: %d\n", failures);
        return 1;
    }
    printf("все проверки пройдены\n");
    return 0;
}
