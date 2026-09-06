/* Разбор IP-пакета до DNS-сообщения. Сокет захвата есть только в Linux,
   а вот эта часть проверяется где угодно — и именно в ней легко
   ошибиться со смещениями. */
#include "dnscap.h"
#include "shadowfox.h"

#include <arpa/inet.h>
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

/* Готовое DNS-сообщение: ответ на example.com с адресом 192.0.2.10. */
static size_t make_dns(unsigned char *b)
{
    static const unsigned char msg[] = {
        0x12, 0x34, 0x81, 0x80,
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        7, 'e','x','a','m','p','l','e', 3, 'c','o','m', 0,
        0x00, 0x01, 0x00, 0x01,
        0xC0, 0x0C,
        0x00, 0x01, 0x00, 0x01,
        0x00, 0x00, 0x01, 0x2C,
        0x00, 0x04,
        192, 0, 2, 10
    };
    memcpy(b, msg, sizeof(msg));
    return sizeof(msg);
}

static size_t build_v4(unsigned char *p, unsigned sport, unsigned proto,
                       unsigned frag_off, int broken_udp_len)
{
    unsigned char dns[512];
    size_t dlen = make_dns(dns);

    size_t ihl = 20;
    memset(p, 0, ihl);
    p[0] = 0x45;                                  /* версия 4, IHL 5 */
    p[6] = (unsigned char)(frag_off >> 8);
    p[7] = (unsigned char)(frag_off & 0xFF);
    p[9] = (unsigned char)proto;

    unsigned char *udp = p + ihl;
    udp[0] = (unsigned char)(sport >> 8);
    udp[1] = (unsigned char)(sport & 0xFF);
    udp[2] = 0xC0; udp[3] = 0x00;                 /* порт назначения */

    unsigned ulen = broken_udp_len ? 9000 : (unsigned)(8 + dlen);
    udp[4] = (unsigned char)(ulen >> 8);
    udp[5] = (unsigned char)(ulen & 0xFF);

    memcpy(udp + 8, dns, dlen);
    return ihl + 8 + dlen;
}

static size_t build_v6(unsigned char *p, unsigned next_header)
{
    unsigned char dns[512];
    size_t dlen = make_dns(dns);

    memset(p, 0, 40);
    p[0] = 0x60;                                  /* версия 6 */
    p[6] = (unsigned char)next_header;

    unsigned char *udp = p + 40;
    udp[0] = 0; udp[1] = 53;
    udp[2] = 0xC0; udp[3] = 0x00;
    unsigned ulen = (unsigned)(8 + dlen);
    udp[4] = (unsigned char)(ulen >> 8);
    udp[5] = (unsigned char)(ulen & 0xFF);

    memcpy(udp + 8, dns, dlen);
    return 40 + 8 + dlen;
}

static void test_v4_reply(void)
{
    unsigned char pkt[1024];
    size_t n = build_v4(pkt, 53, 17, 0, 0);

    dns_reply_t r;
    CHECK(dcap_extract(pkt, n, &r) == 0, "ответ из IPv4-пакета разобран");
    CHECK(!strcmp(r.question, "example.com"), "вопрос: %s", r.question);
    CHECK(r.answer_count == 1, "адрес найден");

    char ip[64];
    inet_ntop(AF_INET, r.answers[0].addr, ip, sizeof(ip));
    CHECK(!strcmp(ip, "192.0.2.10"), "адрес: %s", ip);
}

static void test_v6_reply(void)
{
    unsigned char pkt[1024];
    size_t n = build_v6(pkt, 17);

    dns_reply_t r;
    CHECK(dcap_extract(pkt, n, &r) == 0, "ответ из IPv6-пакета разобран");
    CHECK(!strcmp(r.question, "example.com"), "вопрос из v6");
}

static void test_rejects_wrong_packets(void)
{
    unsigned char pkt[1024];
    dns_reply_t   r;

    /* Не тот порт источника: это не ответ резолвера. */
    size_t n = build_v4(pkt, 5353, 17, 0, 0);
    CHECK(dcap_extract(pkt, n, &r) == -1, "чужой порт отброшен");

    /* Не UDP. */
    n = build_v4(pkt, 53, 6, 0, 0);
    CHECK(dcap_extract(pkt, n, &r) == -1, "TCP отброшен");

    /* Фрагмент: собирать его мы не умеем и разбирать не должны. */
    n = build_v4(pkt, 53, 17, 0x0001, 0);
    CHECK(dcap_extract(pkt, n, &r) == -1, "фрагмент отброшен");

    /* Заголовок расширения вместо UDP в IPv6. */
    n = build_v6(pkt, 44);
    CHECK(dcap_extract(pkt, n, &r) == -1, "расширение v6 отброшено");

    /* Не IP вовсе. */
    memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x00;
    CHECK(dcap_extract(pkt, 100, &r) == -1, "мусор отброшен");

    CHECK(dcap_extract(NULL, 100, &r) == -1, "NULL");
    CHECK(dcap_extract(pkt, 3, &r) == -1, "слишком короткий пакет");
}

static void test_bad_udp_length(void)
{
    /* Длина в заголовке UDP больше самого пакета: верить ей нельзя,
       иначе разбор уйдёт за буфер. */
    unsigned char pkt[1024];
    size_t n = build_v4(pkt, 53, 17, 0, 1);

    dns_reply_t r;
    CHECK(dcap_extract(pkt, n, &r) == 0,
          "завышенная длина UDP не мешает разбору");
    CHECK(!strcmp(r.question, "example.com"), "и данные те же");
}

static void test_truncation_is_safe(void)
{
    unsigned char pkt[1024];
    size_t n = build_v4(pkt, 53, 17, 0, 0);

    dns_reply_t r;
    /* Обрезание в любом месте не должно приводить к чтению за буфером.
       Проверяем весь диапазон: пакеты из сети бывают любыми. */
    for (size_t cut = 1; cut < n; cut++) {
        int rc = dcap_extract(pkt, cut, &r);
        CHECK(rc == 0 || rc == -1, "обрезка на %zu разобрана без падения", cut);
    }
}

static void test_open_reports_platform(void)
{
    dcap_t c;
    dcap_init(&c);
    CHECK(c.fd == -1, "сокет изначально закрыт");

    char err[128] = "";
    int  rc = dcap_open(&c, "нет-такого-интерфейса", err, sizeof(err));
    /* На Linux откажет из-за интерфейса, в остальных системах — из-за
       отсутствия захвата. Важно, что причина названа, а не молчание. */
    CHECK(rc == -1, "открытие несуществующего интерфейса отказано");
    CHECK(err[0] != '\0', "причина заполнена: %s", err);

    dcap_close(&c);
    CHECK(c.fd == -1, "закрытие безопасно и повторно");
}

int main(void)
{
    printf("check_dnscap " VERSION "\n");

    test_v4_reply();
    test_v6_reply();
    test_rejects_wrong_packets();
    test_bad_udp_length();
    test_truncation_is_safe();
    test_open_reports_platform();

    if (failures) {
        printf("ПРОВАЛЕНО проверок: %d\n", failures);
        return 1;
    }
    printf("все проверки пройдены\n");
    return 0;
}
