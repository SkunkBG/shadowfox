/* Подписка: адрес вместо ссылок. Проверяем разбор ответа (base64,
   список, страница), кеш при недоступном сервере и то, что адрес
   подписки не утекает в имя узла. Сеть здесь не трогаем: file://. */
#include "subs.h"
#include "shadowfox.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
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

static char dir[256];

static void put(const char *name, const char *text)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    FILE *f = fopen(path, "w");
    if (f) { fputs(text, f); fclose(f); }
}

static void test_url(void)
{
    CHECK(subs_is_url("https://panel.example.com/api/abc"), "https");
    CHECK(!subs_is_url("http://panel.example.com/x"), "http — открытым текстом нельзя");
    CHECK(!subs_is_url("vless://uuid@host:443?x=1#tag"), "vless не подписка");
    CHECK(!subs_is_url("# https://comment"), "комментарий");

    char host[SUBS_HOST_MAX];
    subs_host("https://panel.example.com/api/-spDDsecret?x=1", host, sizeof(host));
    CHECK(!strcmp(host, "panel.example.com"), "имя узла: %s", host);
    subs_host("https://panel.example.com", host, sizeof(host));
    CHECK(!strcmp(host, "panel.example.com"), "имя узла без пути: %s", host);

    const char *text = "# ссылки\nvless://a@b:1#x\nhttps://one.example/a\n\nhttps://two.example/b\n";
    CHECK(subs_count_urls(text) == 2, "две подписки");
    subs_first_host(text, host, sizeof(host));
    CHECK(!strcmp(host, "one.example"), "первая: %s", host);
    CHECK(subs_count_urls("vless://a@b:1\n") == 0, "без подписок");
}

static void test_fetch(void)
{
    static char out[64 * 1024];
    char err[160] = "";
    char url[512];

    /* base64 от двух ссылок, без выравнивания, как отдают панели. */
    put("b64.txt", "dmxlc3M6Ly9hQGI6NDQzI29uZQp2bGVzczovL2NAZDo0NDMjdHdvCg");
    snprintf(url, sizeof(url), "file://%s/b64.txt", dir);
    long n = subs_fetch(url, NULL, out, sizeof(out), NULL, err, sizeof(err));
    CHECK(n > 0 && strstr(out, "vless://a@b:443#one") && strstr(out, "vless://c@d:443#two"),
          "base64 раскрыт: %ld %s", n, err);

    put("plain.txt", "vless://a@b:443#one\r\nvless://c@d:443#two\r\n");
    snprintf(url, sizeof(url), "file://%s/plain.txt", dir);
    n = subs_fetch(url, NULL, out, sizeof(out), NULL, err, sizeof(err));
    CHECK(n > 0 && strstr(out, "#two"), "список как есть: %ld", n);

    put("page.html", "<!doctype html><html><body>Subscription</body></html>");
    snprintf(url, sizeof(url), "file://%s/page.html", dir);
    n = subs_fetch(url, NULL, out, sizeof(out), NULL, err, sizeof(err));
    CHECK(n < 0 && strstr(err, "страниц"), "страница вместо списка: %s", err);

    put("empty.txt", "\n");
    snprintf(url, sizeof(url), "file://%s/empty.txt", dir);
    n = subs_fetch(url, NULL, out, sizeof(out), NULL, err, sizeof(err));
    CHECK(n < 0, "пустой ответ");

    put("error.json", "{\"statusCode\":404,\"message\":\"Not Found\"}");
    snprintf(url, sizeof(url), "file://%s/error.json", dir);
    n = subs_fetch(url, NULL, out, sizeof(out), NULL, err, sizeof(err));
    CHECK(n < 0 && strstr(err, "ошибк"), "JSON без outbounds — не подписка: %s", err);

    put("cfg.json", "[{\"remarks\":\"A\",\"outbounds\":[{\"tag\":\"proxy\",\"protocol\":\"vless\"}]}]");
    snprintf(url, sizeof(url), "file://%s/cfg.json", dir);
    n = subs_fetch(url, NULL, out, sizeof(out), NULL, err, sizeof(err));
    CHECK(n > 0 && out[0] == '[', "JSON с outbounds принимается: %s", err);

    put("junk.txt", "aGVsbG8gd29ybGQ=");
    snprintf(url, sizeof(url), "file://%s/junk.txt", dir);
    n = subs_fetch(url, NULL, out, sizeof(out), NULL, err, sizeof(err));
    CHECK(n < 0 && strstr(err, "ссылки"), "base64 без ссылок: %s", err);
}

static void test_expand(void)
{
    static char out[64 * 1024];
    char err[160] = "";
    char cache[512], text[1024];
    int  cached = -1;

    snprintf(cache, sizeof(cache), "%s/cache", dir);
    unlink(cache);
    subs_dev_t dev = { "hwid-test", "Keenetic Viva (KN-1910)", "4.3.6" };

    /* Без подписок текст копируется как есть. */
    int rc = subs_expand("vless://a@b:1#x\n", cache, &dev, out, sizeof(out), &cached, NULL, err, sizeof(err));
    CHECK(rc == 0 && !strcmp(out, "vless://a@b:1#x\n"), "без подписок: %d [%s]", rc, out);
    CHECK(access(cache, F_OK) != 0, "кеш без подписок не пишется");

    put("sub.txt", "dmxlc3M6Ly9hQGI6NDQzI29uZQp2bGVzczovL2NAZDo0NDMjdHdvCg");
    snprintf(text, sizeof(text), "# мои\nvless://own@h:443#mine\nfile://%s/sub.txt\n", dir);
    rc = subs_expand(text, cache, &dev, out, sizeof(out), &cached, NULL, err, sizeof(err));
    CHECK(rc == 1 && cached == 0, "одна подписка: %d %d %s", rc, cached, err);
    CHECK(strstr(out, "#mine") && strstr(out, "#one") && strstr(out, "#two"),
          "свои ссылки и подписка вместе");
    CHECK(!strstr(out, "file://"), "адрес подписки в результат не попадает");
    CHECK(access(cache, F_OK) == 0, "кеш записан");

    /* Сервер недоступен — берётся кеш. */
    snprintf(text, sizeof(text), "vless://own@h:443#mine\nfile://%s/missing.txt\n", dir);
    rc = subs_expand(text, cache, &dev, out, sizeof(out), &cached, NULL, err, sizeof(err));
    CHECK(rc == 1 && cached == 1, "из кеша: %d %d %s", rc, cached, err);
    CHECK(strstr(out, "#mine") && strstr(out, "#two"), "кеш содержит прежний список");
    CHECK(err[0], "причина сохранена: %s", err);

    /* Ни сервера, ни кеша — отказ. */
    unlink(cache);
    rc = subs_expand(text, cache, &dev, out, sizeof(out), &cached, NULL, err, sizeof(err));
    CHECK(rc < 0, "без кеша отказ");
}

/* Заголовки ответа: имя провайдера в base64, трафик, срок, период. */
static void test_headers(void)
{
    static char out[64 * 1024];
    char err[160] = "";
    char url[512];
    subs_info_t info;

    const char *hdr =
        "HTTP/1.1 200 OK\r\n"
        "content-type: text/plain; charset=utf-8\r\n"
        "Profile-Title: base64:QmFkZ2VyIFByb3h5IOKYle+4jw==\r\n"
        "profile-update-interval: 1\r\n"
        "subscription-userinfo: upload=10; download=3705019832264; total=0; expire=1806710400\r\n"
        "\r\n";
    subs_parse_headers(hdr, strlen(hdr), &info);
    CHECK(!strcmp(info.title, "Badger Proxy \xe2\x98\x95\xef\xb8\x8f"), "имя из base64 с селектором эмодзи: [%s]", info.title);
    CHECK(info.download == 3705019832264LL && info.upload == 10 && info.total == 0,
          "трафик: %lld %lld %lld", info.download, info.upload, info.total);
    CHECK(info.expire == 1806710400L && info.update_hours == 1, "срок и период: %ld %d", info.expire, info.update_hours);

    subs_parse_headers("profile-title: Plain Name\r\n", 27, &info);
    CHECK(!strcmp(info.title, "Plain Name"), "имя как есть: [%s]", info.title);

    /* Ответ с заголовками и телом base64: заголовки снимаются, тело раскрывается. */
    char full[1024];
    snprintf(full, sizeof(full), "%sdmxlc3M6Ly9hQGI6NDQzI29uZQp2bGVzczovL2NAZDo0NDMjdHdvCg", hdr);
    put("hdr.txt", full);
    snprintf(url, sizeof(url), "file://%s/hdr.txt", dir);
    long n = subs_fetch(url, NULL, out, sizeof(out), &info, err, sizeof(err));
    CHECK(n > 0 && strstr(out, "#two") && !strstr(out, "HTTP/"), "заголовки сняты, тело раскрыто: %ld %s", n, err);
    CHECK(!strncmp(info.title, "Badger Proxy", 12), "имя дошло через fetch: [%s]", info.title);

    /* Два блока (редирект) подряд. */
    snprintf(full, sizeof(full), "HTTP/1.1 302 Found\r\nLocation: /x\r\n\r\n%svless://a@b:443#one\n", hdr);
    put("hdr2.txt", full);
    snprintf(url, sizeof(url), "file://%s/hdr2.txt", dir);
    n = subs_fetch(url, NULL, out, sizeof(out), &info, err, sizeof(err));
    CHECK(n > 0 && !strncmp(out, "vless://", 8) && info.update_hours == 1, "два блока заголовков сняты: %ld", n);
}

int main(void)
{
    printf("check_subs %s\n", VERSION);

    snprintf(dir, sizeof(dir), "/tmp/check_subs.%ld", (long)getpid());
    if (mkdir(dir, 0700) != 0) { printf("  не создать %s\n", dir); return 1; }

    test_url();
    test_fetch();
    test_expand();
    test_headers();

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
    if (system(cmd) != 0) { /* мусор в /tmp не страшен */ }

    if (failures) { printf("  провалов: %d\n", failures); return 1; }
    printf("все проверки пройдены\n");
    return 0;
}
