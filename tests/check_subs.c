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
    CHECK(subs_is_url("http://panel.example.com/x"), "http");
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
    long n = subs_fetch(url, NULL, out, sizeof(out), err, sizeof(err));
    CHECK(n > 0 && strstr(out, "vless://a@b:443#one") && strstr(out, "vless://c@d:443#two"),
          "base64 раскрыт: %ld %s", n, err);

    put("plain.txt", "vless://a@b:443#one\r\nvless://c@d:443#two\r\n");
    snprintf(url, sizeof(url), "file://%s/plain.txt", dir);
    n = subs_fetch(url, NULL, out, sizeof(out), err, sizeof(err));
    CHECK(n > 0 && strstr(out, "#two"), "список как есть: %ld", n);

    put("page.html", "<!doctype html><html><body>Subscription</body></html>");
    snprintf(url, sizeof(url), "file://%s/page.html", dir);
    n = subs_fetch(url, NULL, out, sizeof(out), err, sizeof(err));
    CHECK(n < 0 && strstr(err, "страниц"), "страница вместо списка: %s", err);

    put("empty.txt", "\n");
    snprintf(url, sizeof(url), "file://%s/empty.txt", dir);
    n = subs_fetch(url, NULL, out, sizeof(out), err, sizeof(err));
    CHECK(n < 0, "пустой ответ");

    put("junk.txt", "aGVsbG8gd29ybGQ=");
    snprintf(url, sizeof(url), "file://%s/junk.txt", dir);
    n = subs_fetch(url, NULL, out, sizeof(out), err, sizeof(err));
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
    int rc = subs_expand("vless://a@b:1#x\n", cache, &dev, out, sizeof(out), &cached, err, sizeof(err));
    CHECK(rc == 0 && !strcmp(out, "vless://a@b:1#x\n"), "без подписок: %d [%s]", rc, out);
    CHECK(access(cache, F_OK) != 0, "кеш без подписок не пишется");

    put("sub.txt", "dmxlc3M6Ly9hQGI6NDQzI29uZQp2bGVzczovL2NAZDo0NDMjdHdvCg");
    snprintf(text, sizeof(text), "# мои\nvless://own@h:443#mine\nfile://%s/sub.txt\n", dir);
    rc = subs_expand(text, cache, &dev, out, sizeof(out), &cached, err, sizeof(err));
    CHECK(rc == 1 && cached == 0, "одна подписка: %d %d %s", rc, cached, err);
    CHECK(strstr(out, "#mine") && strstr(out, "#one") && strstr(out, "#two"),
          "свои ссылки и подписка вместе");
    CHECK(!strstr(out, "file://"), "адрес подписки в результат не попадает");
    CHECK(access(cache, F_OK) == 0, "кеш записан");

    /* Сервер недоступен — берётся кеш. */
    snprintf(text, sizeof(text), "vless://own@h:443#mine\nfile://%s/missing.txt\n", dir);
    rc = subs_expand(text, cache, &dev, out, sizeof(out), &cached, err, sizeof(err));
    CHECK(rc == 1 && cached == 1, "из кеша: %d %d %s", rc, cached, err);
    CHECK(strstr(out, "#mine") && strstr(out, "#two"), "кеш содержит прежний список");
    CHECK(err[0], "причина сохранена: %s", err);

    /* Ни сервера, ни кеша — отказ. */
    unlink(cache);
    rc = subs_expand(text, cache, &dev, out, sizeof(out), &cached, err, sizeof(err));
    CHECK(rc < 0, "без кеша отказ");
}

int main(void)
{
    printf("check_subs %s\n", VERSION);

    snprintf(dir, sizeof(dir), "/tmp/check_subs.%ld", (long)getpid());
    if (mkdir(dir, 0700) != 0) { printf("  не создать %s\n", dir); return 1; }

    test_url();
    test_fetch();
    test_expand();

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
    if (system(cmd) != 0) { /* мусор в /tmp не страшен */ }

    if (failures) { printf("  провалов: %d\n", failures); return 1; }
    printf("все проверки пройдены\n");
    return 0;
}
