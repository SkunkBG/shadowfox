/* Маскировка ссылок. Здесь было переполнение стека: хвост правился на
   месте, и при коротком sid= сдвиг выезжал за буфер. Плюс строка без
   схемы — подписка в base64 — уезжала на страницу целиком. */
#include "mask.h"
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

static void test_node_link(void)
{
    char out[1024];
    mask_link("vless://d342d11e-d424-4583-b36e-524ab1f0afa4@example.com:443"
              "?type=tcp&security=reality&pbk=PUBKEY&sid=6ba85179&fp=chrome#tag",
              out, sizeof(out));

    CHECK(strstr(out, "d342d11e") == NULL, "uuid остался: %s", out);
    CHECK(strstr(out, "6ba85179") == NULL, "sid остался: %s", out);
    CHECK(strstr(out, "sid=****") != NULL, "sid не заменён: %s", out);
    CHECK(strstr(out, "&fp=chrome#tag") != NULL, "хвост после sid потерян: %s", out);
    CHECK(strstr(out, "example.com:443") != NULL, "адрес должен быть виден: %s", out);
    CHECK(strncmp(out, "vless://" MASK_MARK "@", 8 + 12 + 1) == 0, "начало: %s", out);
}

/* Пустой sid= у Reality штатен. Раньше на длинной ссылке это писало за
   границу буфера. Проверяем и результат, и что ничего не рвётся на
   каждой длине. */
static void test_empty_sid_long(void)
{
    char link[2048];
    char filler[1200];
    memset(filler, 'x', sizeof(filler) - 1);
    filler[sizeof(filler) - 1] = '\0';

    snprintf(link, sizeof(link),
             "vless://uuid@host:443?pbk=%s&sid=&fp=chrome#r", filler);

    char out[4096];
    mask_link(link, out, sizeof(out));
    CHECK(strstr(out, "sid=****&fp=chrome#r") != NULL, "пустой sid: %s", out + strlen(out) - 40);
    CHECK(strstr(out, "uuid") == NULL, "uuid остался");

    /* sid= в самом конце, без значения и без хвоста. */
    snprintf(link, sizeof(link), "vless://uuid@host:443?pbk=%s&sid=", filler);
    mask_link(link, out, sizeof(out));
    CHECK(strlen(out) > 0, "пусто");
    CHECK(strstr(out, "sid=****") != NULL, "sid в конце: %s", out + strlen(out) - 20);

    /* Маленький выходной буфер — усечение, не переполнение. */
    char small[40];
    mask_link(link, small, sizeof(small));
    CHECK(strlen(small) < sizeof(small), "усечение в маленький буфер");
}

static void test_subscription_url(void)
{
    char out[256];
    mask_link("https://panel.example.com/sub/SECRETTOKEN?x=1", out, sizeof(out));
    CHECK(strcmp(out, "https://panel.example.com/" MASK_MARK) == 0, "подписка: %s", out);
}

static void test_base64_body(void)
{
    char out[256];
    /* Тело подписки: base64, без схемы. Раньше уезжало как есть. */
    mask_link("dmxlc3M6Ly91dWlkQGhvc3Q6NDQzP3R5cGU9dGNwI3Rlc3Q=", out, sizeof(out));
    CHECK(strcmp(out, MASK_MARK) == 0, "base64 не замаскирован: %s", out);

    mask_link("", out, sizeof(out));
    CHECK(out[0] == '\0', "пустая строка остаётся пустой");
}

static void test_nodes_multiline(void)
{
    char out[2048];
    mask_nodes("# комментарий\n"
               "vless://uuid@a.example.com:443?sid=ab#one\n"
               "\n"
               "dmxlc3M6Ly8=\n",
               out, sizeof(out));

    CHECK(strstr(out, "# комментарий\n") != NULL, "комментарий виден как есть");
    CHECK(strstr(out, "vless://" MASK_MARK "@a.example.com:443?sid=****#one\n") != NULL,
          "узел: %s", out);
    CHECK(strstr(out, "\n\n") != NULL, "пустая строка сохранена");
    CHECK(strstr(out, "dmxlc3M6") == NULL, "base64 в списке остался");

    /* Строка длиннее лимита не должна выглядеть как ссылка. */
    char longline[1500];
    memset(longline, 'a', sizeof(longline) - 1);
    memcpy(longline, "vless://", 8);
    longline[sizeof(longline) - 1] = '\0';
    mask_nodes(longline, out, sizeof(out));
    CHECK(strcmp(out, MASK_MARK "\n") == 0, "длинная строка: %.20s", out);
}

int main(void)
{
    printf("check_mask %s\n", VERSION);

    test_node_link();
    test_empty_sid_long();
    test_subscription_url();
    test_base64_body();
    test_nodes_multiline();

    if (failures) {
        printf("ПРОВАЛЕНО проверок: %d\n", failures);
        return 1;
    }
    printf("все проверки пройдены\n");
    return 0;
}
