/* Разбор DNS-ответов. Байты приходят прямо из сети, поэтому половина
   тестов — про мусор: обрезанные пакеты, ссылки за границу буфера и
   петли из указателей сжатия. */
#include "dnsmsg.h"
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

/* Небольшой сборщик пакетов, чтобы тесты читались, а не считали байты.
   Размер с запасом: тест на переполнение списка ответов собирает пакет
   на полтора килобайта, и на 1024 байтах помощник молча писал за
   границу массива — тест падал раньше, чем печатал хоть строку. */
typedef struct { unsigned char b[4096]; size_t n; } pkt_t;

static void put8(pkt_t *p, unsigned v)
{
    /* Лучше оборвать сборку, чем испортить стек: помощник должен
       ломаться заметно. */
    if (p->n >= sizeof(p->b)) {
        printf("  ПРОВАЛ: сборщик пакета переполнен\n");
        failures++;
        return;
    }
    p->b[p->n++] = (unsigned char)v;
}
static void put16(pkt_t *p, unsigned v) { put8(p, v >> 8); put8(p, v & 0xFF); }
static void put32(pkt_t *p, unsigned v) { put16(p, v >> 16); put16(p, v & 0xFFFF); }

static void put_name(pkt_t *p, const char *name)
{
    const char *s = name;
    while (*s) {
        const char *dot = strchr(s, '.');
        size_t len = dot ? (size_t)(dot - s) : strlen(s);
        put8(p, (unsigned)len);
        if (p->n + len > sizeof(p->b)) { failures++; return; }
        memcpy(p->b + p->n, s, len);
        p->n += len;
        if (!dot) break;
        s = dot + 1;
    }
    put8(p, 0);
}

static void header(pkt_t *p, unsigned flags, unsigned qd, unsigned an)
{
    p->n = 0;
    put16(p, 0x1234);
    put16(p, flags);
    put16(p, qd);
    put16(p, an);
    put16(p, 0);
    put16(p, 0);
}

static void question(pkt_t *p, const char *name, unsigned type)
{
    put_name(p, name);
    put16(p, type);
    put16(p, 1);
}

static void answer_a(pkt_t *p, const char *name, const char *ip)
{
    put_name(p, name);
    put16(p, 1);          /* A */
    put16(p, 1);          /* IN */
    put32(p, 300);
    put16(p, 4);
    unsigned char a[4];
    inet_pton(AF_INET, ip, a);
    memcpy(p->b + p->n, a, 4);
    p->n += 4;
}

static void test_simple_a(void)
{
    pkt_t p;
    header(&p, 0x8180, 1, 1);
    question(&p, "example.com", 1);
    answer_a(&p, "example.com", "192.0.2.10");

    dns_reply_t r;
    CHECK(dns_parse_reply(p.b, p.n, &r) == 0, "ответ разобран");
    CHECK(!strcmp(r.question, "example.com"), "вопрос: %s", r.question);
    CHECK(r.answer_count == 1, "одна запись");
    CHECK(r.answers[0].family == 4, "семейство v4");

    char ip[64];
    inet_ntop(AF_INET, r.answers[0].addr, ip, sizeof(ip));
    CHECK(!strcmp(ip, "192.0.2.10"), "адрес: %s", ip);
    CHECK(r.answers[0].ttl == 300, "ttl");
}

static void test_case_is_normalised(void)
{
    pkt_t p;
    header(&p, 0x8180, 1, 1);
    question(&p, "ExAmPlE.CoM", 1);
    answer_a(&p, "ExAmPlE.CoM", "192.0.2.10");

    dns_reply_t r;
    CHECK(dns_parse_reply(p.b, p.n, &r) == 0, "разобран");
    /* Со списком доменов сравниваем в нижнем регистре, приводим сразу. */
    CHECK(!strcmp(r.question, "example.com"), "имя в нижнем регистре: %s",
          r.question);
}

static void test_cname_chain(void)
{
    /* Спросили youtube.com, получили CNAME на googlevideo.com и уже его
       адрес. Владелец адресной записи — цель псевдонима, и она должна
       дойти до вызывающего: правило может быть написано на любую из них. */
    pkt_t p;
    header(&p, 0x8180, 1, 2);
    question(&p, "youtube.com", 1);

    put_name(&p, "youtube.com");
    put16(&p, 5);          /* CNAME */
    put16(&p, 1);
    put32(&p, 60);
    pkt_t tmp; tmp.n = 0;
    put_name(&tmp, "googlevideo.com");
    put16(&p, (unsigned)tmp.n);
    memcpy(p.b + p.n, tmp.b, tmp.n);
    p.n += tmp.n;

    answer_a(&p, "googlevideo.com", "142.250.74.78");

    dns_reply_t r;
    CHECK(dns_parse_reply(p.b, p.n, &r) == 0, "цепочка разобрана");
    CHECK(!strcmp(r.question, "youtube.com"), "вопрос сохранён");
    CHECK(r.answer_count == 1, "одна адресная запись");
    CHECK(!strcmp(r.answers[0].name, "googlevideo.com"),
          "владелец записи — цель псевдонима: %s", r.answers[0].name);
}

static void test_compression_pointer(void)
{
    pkt_t p;
    header(&p, 0x8180, 1, 1);
    size_t qname_at = p.n;
    question(&p, "example.com", 1);

    /* Владелец записи задан указателем на имя в вопросе. */
    put16(&p, 0xC000 | (unsigned)qname_at);
    put16(&p, 1);
    put16(&p, 1);
    put32(&p, 120);
    put16(&p, 4);
    unsigned char a[4];
    inet_pton(AF_INET, "198.51.100.1", a);
    memcpy(p.b + p.n, a, 4);
    p.n += 4;

    dns_reply_t r;
    CHECK(dns_parse_reply(p.b, p.n, &r) == 0, "сжатое имя разобрано");
    CHECK(!strcmp(r.answers[0].name, "example.com"),
          "имя восстановлено: %s", r.answers[0].name);
}

static void test_aaaa(void)
{
    pkt_t p;
    header(&p, 0x8180, 1, 1);
    question(&p, "v6.example.com", 28);

    put_name(&p, "v6.example.com");
    put16(&p, 28);
    put16(&p, 1);
    put32(&p, 60);
    put16(&p, 16);
    unsigned char a[16];
    inet_pton(AF_INET6, "2001:db8::1", a);
    memcpy(p.b + p.n, a, 16);
    p.n += 16;

    dns_reply_t r;
    CHECK(dns_parse_reply(p.b, p.n, &r) == 0, "AAAA разобран");
    CHECK(r.answers[0].family == 6, "семейство v6");

    char ip[64];
    inet_ntop(AF_INET6, r.answers[0].addr, ip, sizeof(ip));
    CHECK(!strcmp(ip, "2001:db8::1"), "адрес v6: %s", ip);
}

static void test_rejects_non_answers(void)
{
    dns_reply_t r;
    pkt_t p;

    /* Запрос, а не ответ. */
    header(&p, 0x0100, 1, 0);
    question(&p, "example.com", 1);
    CHECK(dns_parse_reply(p.b, p.n, &r) == -2, "запрос: ответа нет, но пакет цел");

    /* Ответ с ошибкой: адресов в нём нет. */
    header(&p, 0x8183, 1, 1);
    question(&p, "example.com", 1);
    answer_a(&p, "example.com", "192.0.2.1");
    CHECK(dns_parse_reply(p.b, p.n, &r) == -2, "NXDOMAIN: пакет цел, адресов нет");

    /* Ответ без записей. */
    header(&p, 0x8180, 1, 0);
    question(&p, "example.com", 1);
    CHECK(dns_parse_reply(p.b, p.n, &r) == -2, "пустой ответ: пакет цел");

    /* Только CNAME, без адресов — заворачивать нечего. */
    header(&p, 0x8180, 1, 1);
    question(&p, "a.example.com", 1);
    put_name(&p, "a.example.com");
    put16(&p, 5); put16(&p, 1); put32(&p, 60);
    pkt_t t; t.n = 0; put_name(&t, "b.example.com");
    put16(&p, (unsigned)t.n);
    memcpy(p.b + p.n, t.b, t.n); p.n += t.n;
    CHECK(dns_parse_reply(p.b, p.n, &r) == -2, "только CNAME: пакет цел");

    /* А вот это уже поломка, и путать её с пустотой нельзя: на счётчике
       «битых» строится вывод о том, что перехват смотрит не на тот слой. */
    header(&p, 0x8180, 1, 1);
    question(&p, "example.com", 1);
    p.n -= 3;
    CHECK(dns_parse_reply(p.b, p.n, &r) == -1, "обрезанный пакет — битый");

    CHECK(dns_parse_reply(p.b, 4, &r) == -1, "огрызок — битый");
}

static void test_survives_garbage(void)
{
    dns_reply_t r;
    pkt_t p;

    CHECK(dns_parse_reply(NULL, 100, &r) == -1, "NULL");
    CHECK(dns_parse_reply(p.b, 0, &r) == -1, "нулевая длина");

    header(&p, 0x8180, 1, 1);
    CHECK(dns_parse_reply(p.b, 5, &r) == -1, "обрезанный заголовок");

    /* Обрезание в любом месте не должно приводить к чтению за буфером. */
    header(&p, 0x8180, 1, 1);
    question(&p, "example.com", 1);
    answer_a(&p, "example.com", "192.0.2.10");
    for (size_t cut = 1; cut < p.n; cut++)
        CHECK(dns_parse_reply(p.b, cut, &r) == -1 ||
              dns_parse_reply(p.b, cut, &r) == 0,
              "обрезка на %zu не роняет разбор", cut);

    /* Указатель сжатия вперёд — верный признак петли. */
    header(&p, 0x8180, 1, 1);
    size_t at = p.n;
    put16(&p, 0xC000 | (unsigned)(at + 2));
    put16(&p, 1); put16(&p, 1); put32(&p, 60); put16(&p, 4);
    put32(&p, 0x01020304);
    CHECK(dns_parse_reply(p.b, p.n, &r) == -1, "указатель вперёд отброшен");

    /* Указатель сам на себя. */
    header(&p, 0x8180, 1, 1);
    at = p.n;
    put16(&p, 0xC000 | (unsigned)at);
    CHECK(dns_parse_reply(p.b, p.n, &r) == -1, "указатель на себя отброшен");

    /* Длина записи, уходящая за пакет. */
    header(&p, 0x8180, 1, 1);
    question(&p, "example.com", 1);
    put_name(&p, "example.com");
    put16(&p, 1); put16(&p, 1); put32(&p, 60);
    put16(&p, 4000);
    CHECK(dns_parse_reply(p.b, p.n, &r) == -1, "длина за границей отброшена");
}

static void test_many_answers(void)
{
    pkt_t p;
    unsigned n = DNS_ANSWERS_MAX + 5;
    header(&p, 0x8180, 1, n);
    question(&p, "many.example.com", 1);
    for (unsigned i = 0; i < n; i++) {
        char ip[32];
        snprintf(ip, sizeof(ip), "192.0.2.%u", i + 1);
        answer_a(&p, "many.example.com", ip);
    }

    dns_reply_t r;
    CHECK(dns_parse_reply(p.b, p.n, &r) == 0, "разобран");
    CHECK(r.answer_count == DNS_ANSWERS_MAX, "взято сколько влезло: %d",
          r.answer_count);
    /* Лишнее не теряется молча — оно посчитано. */
    CHECK(r.dropped == 5, "остальное посчитано: %d", r.dropped);
}

int main(void)
{
    printf("check_dnsmsg " VERSION "\n");

    test_simple_a();
    test_case_is_normalised();
    test_cname_chain();
    test_compression_pointer();
    test_aaaa();
    test_rejects_non_answers();
    test_survives_garbage();
    test_many_answers();

    if (failures) {
        printf("ПРОВАЛЕНО проверок: %d\n", failures);
        return 1;
    }
    printf("все проверки пройдены\n");
    return 0;
}
