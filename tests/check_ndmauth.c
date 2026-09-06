/* Разбор ответа роутера и счёт ответа на его запрос. Проверяется на
   настоящем ответе Keenetic Ultra: realm там с пробелом, имя куки у
   каждой сессии своё, а рядом лежит ещё и WWW-Authenticate с теми же
   значениями — легко разобрать не тот заголовок. */
#include "ndmauth.h"
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

static const char REAL[] =
    "HTTP/1.1 401 Unauthorized\r\n"
    "Server: Web server\r\n"
    "Transfer-Encoding: chunked\r\n"
    "Connection: keep-alive\r\n"
    "Set-Cookie: cKXCCNAORweL5v=B9y87zLZ86agdDej; Path=/; Max-Age=300; "
    "SameSite=Strict; HttpOnly\r\n"
    "X-Ndm-Product: Ultra\r\n"
    "WWW-Authenticate: x-ndw2-interactive realm=\"Keenetic Ultra\" "
    "challenge=\"HezSRqszvCRSiWxqDcEhwapwiSgTjmz8\" "
    "session_id=\"B9y87zLZ86agdDej\" session_cookie=\"cKXCCNAORweL5v\"\r\n"
    "X-NDM-Realm: Keenetic Ultra\r\n"
    "X-NDM-Challenge: HezSRqszvCRSiWxqDcEhwapwiSgTjmz8\r\n"
    "\r\n";

static void test_headers(void)
{
    char v[128];

    CHECK(ndm_header(REAL, "X-NDM-Realm", v, sizeof(v)), "realm найден");
    CHECK(!strcmp(v, "Keenetic Ultra"), "realm целиком, с пробелом: «%s»", v);

    CHECK(ndm_header(REAL, "X-NDM-Challenge", v, sizeof(v)), "challenge найден");
    CHECK(!strcmp(v, "HezSRqszvCRSiWxqDcEhwapwiSgTjmz8"), "challenge: «%s»", v);

    /* Имя куки у каждой сессии своё, поэтому берём заголовок целиком. */
    CHECK(ndm_header(REAL, "Set-Cookie", v, sizeof(v)), "кука найдена");
    CHECK(!strncmp(v, "cKXCCNAORweL5v=B9y87zLZ86agdDej;", 32),
          "кука с начала: «%s»", v);

    /* Регистр в заголовках произвольный: у роутера рядом X-Ndm-Product. */
    CHECK(ndm_header(REAL, "x-ndm-realm", v, sizeof(v)), "регистр не важен");

    CHECK(!ndm_header(REAL, "X-NDM-Nothing", v, sizeof(v)), "чего нет — того нет");
    CHECK(v[0] == '\0', "и значение пустое");

    /* Имя, встречающееся только внутри другого заголовка, не считается:
       "realm" есть в WWW-Authenticate, но своего заголовка нет. */
    CHECK(!ndm_header(REAL, "realm", v, sizeof(v)),
          "часть чужого заголовка не заголовок");
}

static void test_answer(void)
{
    char out[65];

    /* md5("admin:Keenetic Ultra:s3cret") = 9603cb573e7c23e791040fd193df9da8,
       затем sha256 от challenge с этим hex. Значение посчитано
       независимо, чужой реализацией. */
    ndm_answer("Keenetic Ultra", "HezSRqszvCRSiWxqDcEhwapwiSgTjmz8",
               "admin", "s3cret", out);

    CHECK(strlen(out) == 64, "ответ длиной 64: %zu", strlen(out));
    CHECK(!strcmp(out, "d77ad3bdb51e14cdb79df4f27922eca8f2397f3bdb5ef2b4520bab110ef948f9"),
          "ответ: %s", out);
}

int main(void)
{
    printf("check_ndmauth " VERSION "\n");

    test_headers();
    test_answer();

    if (failures) {
        printf("ПРОВАЛЕНО проверок: %d\n", failures);
        return 1;
    }
    printf("все проверки пройдены\n");
    return 0;
}
