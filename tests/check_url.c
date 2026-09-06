/* Тесты разбора share-ссылок. Именно здесь neofit терял данные:
   он брал не все параметры и подставлял свои вместо пришедших. */
#include "shadowfox.h"
#include "url.h"

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

static void test_pct_decode(void)
{
    char out[64];

    CHECK(url_pct_decode("%2F", out, sizeof(out)) == 0 && !strcmp(out, "/"),
          "%%2F это слэш");
    CHECK(url_pct_decode("a%20b", out, sizeof(out)) == 0 && !strcmp(out, "a b"),
          "%%20 это пробел");
    CHECK(url_pct_decode("h2%2Chttp%2F1.1", out, sizeof(out)) == 0 &&
          !strcmp(out, "h2,http/1.1"), "список alpn декодируется");

    /* '+' в URL — обычный символ, а не пробел: так кодируют тело формы,
       а не строку запроса. Ошибка тут ломает пароли и base64. */
    CHECK(url_pct_decode("a+b", out, sizeof(out)) == 0 && !strcmp(out, "a+b"),
          "плюс остаётся плюсом");

    /* Битый процент не должен ронять разбор всей ссылки. */
    CHECK(url_pct_decode("100%", out, sizeof(out)) == 0 && !strcmp(out, "100%"),
          "одинокий процент проходит как есть");
    CHECK(url_pct_decode("%zz", out, sizeof(out)) == 0 && !strcmp(out, "%zz"),
          "неверная шестнадцатеричная пара проходит как есть");

    char tiny[4];
    CHECK(url_pct_decode("длинная строка", tiny, sizeof(tiny)) == -1,
          "переполнение буфера отлавливается");
}

static void test_vless_reality(void)
{
    const char *link =
        "vless://d342d11e-d424-4583-b36e-524ab1f0afa4@example.com:443"
        "?type=tcp&security=reality&pbk=xO5F9nQ&fp=chrome&sni=www.google.com"
        "&sid=6ba85179e30d4fc2&spx=%2F&flow=xtls-rprx-vision&encryption=none"
        "#%D0%9C%D0%BE%D0%B9%20%D1%81%D0%B5%D1%80%D0%B2%D0%B5%D1%80";

    url_t u;
    CHECK(url_parse(link, &u) == 0, "ссылка разобрана");
    CHECK(!strcmp(u.scheme, "vless"), "схема vless");
    CHECK(!strcmp(u.user, "d342d11e-d424-4583-b36e-524ab1f0afa4"), "uuid");
    CHECK(!strcmp(u.host, "example.com"), "хост");
    CHECK(u.port == 443, "порт");
    CHECK(!strcmp(u.fragment, "Мой сервер"), "имя из фрагмента декодировано");

    char v[256];
    CHECK(url_query_get(&u, "security", v, sizeof(v)) == 1 &&
          !strcmp(v, "reality"), "security");
    CHECK(url_query_get(&u, "fp", v, sizeof(v)) == 1 && !strcmp(v, "chrome"),
          "fp");
    CHECK(url_query_get(&u, "spx", v, sizeof(v)) == 1 && !strcmp(v, "/"),
          "spx декодирован");
    CHECK(url_query_get(&u, "flow", v, sizeof(v)) == 1 &&
          !strcmp(v, "xtls-rprx-vision"), "flow");
    CHECK(url_query_get(&u, "нетТакого", v, sizeof(v)) == 0,
          "отсутствующий параметр даёт 0");

    /* Регрессия на подстроку: 'ni' не должен находиться внутри 'sni'. */
    CHECK(url_query_get(&u, "ni", v, sizeof(v)) == 0,
          "имя параметра сравнивается целиком, а не как подстрока");
    CHECK(url_query_get(&u, "sni", v, sizeof(v)) == 1 &&
          !strcmp(v, "www.google.com"), "sni");
}

static void test_alpn_not_lost(void)
{
    /* neofit жёстко прописывал alpn ["h2","http/1.1"] и игнорировал
       пришедший в ссылке. Рассогласование alpn с заявленным отпечатком
       uTLS — сигнал для DPI, и это надо уметь читать из ссылки. */
    const char *link = "vless://uuid@host:443?security=tls&alpn=h3%2Ch2";

    url_t u;
    char  v[64];
    CHECK(url_parse(link, &u) == 0, "ссылка с alpn разобрана");
    CHECK(url_query_get(&u, "alpn", v, sizeof(v)) == 1 && !strcmp(v, "h3,h2"),
          "alpn берётся из ссылки, а не подставляется своим");
}

static void test_edge_cases(void)
{
    url_t u;

    CHECK(url_parse("vless://host", &u) == 0 && u.port == 0,
          "без порта — порт 0");
    CHECK(url_parse("vless://[2001:db8::1]:8443", &u) == 0, "IPv6 разобран");
    CHECK(!strcmp(u.host, "2001:db8::1"), "IPv6 без скобок");
    CHECK(u.host_is_ipv6 == 1, "IPv6 помечен");
    CHECK(u.port == 8443, "порт после IPv6");

    CHECK(url_parse("vless://u@h:443/some/path?a=1", &u) == 0, "путь и query");
    CHECK(!strcmp(u.path, "/some/path"), "путь отделён");
    CHECK(!strcmp(u.host, "h"), "хост не съел путь");

    CHECK(url_parse("не ссылка", &u) == -1, "мусор отвергнут");
    CHECK(url_parse("vless://", &u) == -1, "пустой хост отвергнут");
    CHECK(url_parse("vless://h:99999", &u) == -1, "порт вне диапазона отвергнут");
    CHECK(url_parse(NULL, &u) == -1, "NULL отвергнут");
}

int main(void)
{
    printf("check_url " VERSION "\n");

    test_pct_decode();
    test_vless_reality();
    test_alpn_not_lost();
    test_edge_cases();

    if (failures) {
        printf("ПРОВАЛЕНО проверок: %d\n", failures);
        return 1;
    }
    printf("все проверки пройдены\n");
    return 0;
}
