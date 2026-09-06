#include "base64.h"
#include "nodelist.h"
#include "shadowfox.h"
#include "xraycfg.h"

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

static void test_base64(void)
{
    char out[256];

    CHECK(base64_decode("aGVsbG8=", out, sizeof(out)) == 5 &&
          !strcmp(out, "hello"), "обычный base64");

    /* Подписки сплошь и рядом приходят без выравнивания. */
    CHECK(base64_decode("aGVsbG8", out, sizeof(out)) == 5 &&
          !strcmp(out, "hello"), "без символов выравнивания");

    /* И с переводами строк внутри. */
    CHECK(base64_decode("aGVs\nbG8=\n", out, sizeof(out)) == 5 &&
          !strcmp(out, "hello"), "с переводами строк");

    /* URL-safe алфавит: '-' и '_' вместо '+' и '/'. */
    char plus[64], dash[64];
    CHECK(base64_decode("++//", plus, sizeof(plus)) == 3, "обычный алфавит");
    CHECK(base64_decode("--__", dash, sizeof(dash)) == 3, "URL-safe алфавит");
    CHECK(memcmp(plus, dash, 3) == 0, "оба алфавита дают одно и то же");

    CHECK(base64_decode("не base64!", out, sizeof(out)) == -1,
          "недопустимый символ отвергнут");

    char tiny[4];
    CHECK(base64_decode("aGVsbG8gd29ybGQ=", tiny, sizeof(tiny)) == -1,
          "нехватка буфера отлавливается");
}

#define L1 "vless://uuid@a.example.com:443?security=reality&pbk=K#Узел"
#define L2 "vless://uuid@b.example.com:8443?type=ws&security=tls#Узел"
#define L3 "vless://uuid@c.example.com:443#Третий"

static void test_plain_list(void)
{
    nodelist_t l;
    nodelist_init(&l);

    const char *body = L1 "\n\n# комментарий\n" L2 "\nэто не ссылка\n" L3 "\n";

    CHECK(nodelist_from_subscription(&l, body) == 3, "разобрано три узла");
    CHECK(l.count == 3, "count");
    /* Одна битая строка не должна ронять всю подписку. */
    CHECK(l.skipped == 1, "битая строка посчитана, но не фатальна");

    /* Совпадающие имена в подписке — норма, а вот совпадающие теги
       в конфиге Xray ломают маршрутизацию молча. */
    CHECK(strcmp(l.items[0].tag, l.items[1].tag) != 0, "теги разведены");
    CHECK(!strcmp(l.items[0].tag, "Узел"), "первый тег как в ссылке");
    CHECK(!strcmp(l.items[1].tag, "Узел #2"), "второй получил номер: %s",
          l.items[1].tag);
}

static void test_base64_subscription(void)
{
    nodelist_t l;
    nodelist_init(&l);

    /* base64 от "L1\nL3" */
    const char *body =
        "dmxlc3M6Ly91dWlkQGEuZXhhbXBsZS5jb206NDQzP3NlY3VyaXR5PXJlYWxpdHkmcGJr"
        "PUsjJUQwJUEzJUQwJUI3JUQwJUI1JUQwJUJCCnZsZXNzOi8vdXVpZEBjLmV4YW1wbGUu"
        "Y29tOjQ0Mw==";

    CHECK(nodelist_from_subscription(&l, body) == 2,
          "подписка в base64 разобрана, узлов %d", l.count);
    CHECK(!strcmp(l.items[0].address, "a.example.com"), "первый адрес");
    CHECK(!strcmp(l.items[1].address, "c.example.com"), "второй адрес");
}

static void test_balancer_appears_only_for_many(void)
{
    char cfg[65536];

    xraycfg_opts_t o;
    xraycfg_defaults(&o);

    nodelist_t one;
    nodelist_init(&one);
    CHECK(nodelist_add_link(&one, L1, NULL, 0) == 0, "один узел добавлен");
    CHECK(xraycfg_build_list(&one, &o, cfg, sizeof(cfg)) == 0, "конфиг на один узел");
    CHECK(strstr(cfg, "balancer") == NULL, "на одном узле балансировщика нет");
    CHECK(strstr(cfg, "observatory") == NULL, "и наблюдателя тоже нет");
    CHECK(strstr(cfg, "\"outboundTag\":\"proxy-0\"") != NULL,
          "правило указывает прямо на узел");

    nodelist_t many;
    nodelist_init(&many);
    CHECK(nodelist_add_link(&many, L1, NULL, 0) == 0, "узел 1");
    CHECK(nodelist_add_link(&many, L2, NULL, 0) == 0, "узел 2");
    CHECK(xraycfg_build_list(&many, &o, cfg, sizeof(cfg)) == 0, "конфиг на два узла");
    CHECK(strstr(cfg, "\"balancerTag\":\"balancer\"") != NULL,
          "правило указывает на балансировщик");
    CHECK(strstr(cfg, "\"type\":\"leastPing\"") != NULL, "стратегия leastPing");
    /* Селектор балансировщика и наблюдателя обязан совпадать с префиксом
       тегов исходящих, иначе они не найдут ни одного узла. */
    CHECK(strstr(cfg, "\"selector\":[\"proxy-\"]") != NULL, "селектор");
    CHECK(strstr(cfg, "\"subjectSelector\":[\"proxy-\"]") != NULL, "субъекты");
    CHECK(strstr(cfg, "\"tag\":\"proxy-0\"") != NULL, "тег узла 0");
    CHECK(strstr(cfg, "\"tag\":\"proxy-1\"") != NULL, "тег узла 1");
}

static void test_empty_list(void)
{
    char       cfg[1024];
    nodelist_t l;
    nodelist_init(&l);

    xraycfg_opts_t o;
    xraycfg_defaults(&o);

    CHECK(xraycfg_build_list(&l, &o, cfg, sizeof(cfg)) == -1,
          "пустой список — ошибка, а не конфиг без исходящих");
    CHECK(nodelist_from_subscription(&l, "сплошной мусор\nи ещё") == 0,
          "подписка без ссылок даёт ноль узлов");
}

static void test_overflow_of_list(void)
{
    nodelist_t l;
    nodelist_init(&l);

    for (int i = 0; i < NODELIST_MAX; i++)
        CHECK(nodelist_add_link(&l, L3, NULL, 0) == 0, "узел %d добавлен", i);

    char err[128] = "";
    CHECK(nodelist_add_link(&l, L3, err, sizeof(err)) == -1,
          "сверх лимита не добавляется");
    CHECK(err[0] != '\0', "причина заполнена");
}

int main(void)
{
    printf("check_nodelist " VERSION "\n");

    test_base64();
    test_plain_list();
    test_base64_subscription();
    test_balancer_appears_only_for_many();
    test_empty_list();
    test_overflow_of_list();

    if (failures) {
        printf("ПРОВАЛЕНО проверок: %d\n", failures);
        return 1;
    }
    printf("все проверки пройдены\n");
    return 0;
}
