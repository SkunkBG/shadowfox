/* Перехват имени из TLS ClientHello: разбор пакета и фильтр ядра.

   Фильтр проверяется здесь не для полноты. Ошибка в нём не ломает
   сборку и ничего не пишет в журнал — сокет живой, счётчики идут,
   совпадений просто нет. Ровно так уже случилось с фильтром DNS, где
   байткод был рассчитан на кадр Ethernet, а сокет отдавал IP-пакет.
   Поэтому тот же массив прогоняется здесь через свой интерпретатор. */
#include "snicap.h"
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

/* ---- интерпретатор cBPF ----

   Ровно те команды, что встречаются в нашем фильтре. Незнакомая
   команда — это провал теста, а не молчаливый пропуск: иначе можно
   «проверить» фильтр, половину которого мы не выполнили. */
static int bpf_run(const scap_insn_t *f, unsigned n,
                   const unsigned char *pkt, unsigned len, int *bad)
{
    unsigned A = 0, X = 0;
    unsigned pc = 0;

    for (; pc < n; pc++) {
        const scap_insn_t *i = &f[pc];
        unsigned k = i->k;

        switch (i->code) {
        case 0x30:                                   /* ldb [k] */
            if (k >= len) return 0;
            A = pkt[k];
            break;
        case 0x28:                                   /* ldh [k] */
            if (k + 1 >= len) return 0;
            A = (unsigned)pkt[k] << 8 | pkt[k + 1];
            break;
        case 0x50:                                   /* ldb [x+k] */
            if (X + k >= len) return 0;
            A = pkt[X + k];
            break;
        case 0x48:                                   /* ldh [x+k] */
            if (X + k + 1 >= len) return 0;
            A = (unsigned)pkt[X + k] << 8 | pkt[X + k + 1];
            break;
        case 0xb1:                                   /* ldx 4*([k]&0xf) */
            if (k >= len) return 0;
            X = (unsigned)(pkt[k] & 0x0f) * 4;
            break;
        case 0x54: A &= k; break;                    /* and #k */
        case 0x74: A >>= k; break;                   /* rsh #k */
        case 0x04: A += k; break;                    /* add #k */
        case 0x0c: A += X; break;                    /* add x */
        case 0x07: X = A; break;                     /* tax */
        case 0x15:                                   /* jeq #k */
            pc += (A == k) ? i->jt : i->jf;
            break;
        case 0x45:                                   /* jset #k */
            pc += (A & k) ? i->jt : i->jf;
            break;
        case 0x06:                                   /* ret #k */
            return (int)k;
        default:
            *bad = 1;
            printf("  ПРОВАЛ: неизвестная команда 0x%x на %u\n", i->code, pc);
            return 0;
        }
    }

    *bad = 1;
    printf("  ПРОВАЛ: фильтр досчитал до конца без ret\n");
    return 0;
}

static int filter_takes(const unsigned char *pkt, size_t len)
{
    unsigned n = 0;
    const scap_insn_t *f = scap_filter(&n);
    int bad = 0;
    int r = bpf_run(f, n, pkt, (unsigned)len, &bad);
    if (bad) failures++;
    return r != 0;
}

/* ---- сборка пакетов ---- */

/* ClientHello с заданным именем. Возвращает длину. */
static size_t make_hello(unsigned char *b, const char *name, int with_sni)
{
    size_t nlen = name ? strlen(name) : 0;
    size_t i    = 0;

    b[i++] = 0x16;                     /* handshake */
    b[i++] = 0x03; b[i++] = 0x01;      /* версия записи */
    size_t reclen_at = i; i += 2;      /* длина записи — заполним потом */

    size_t body = i;
    b[i++] = 0x01;                     /* ClientHello */
    size_t hslen_at = i; i += 3;

    b[i++] = 0x03; b[i++] = 0x03;      /* версия */
    memset(b + i, 0xAB, 32); i += 32;  /* random */
    b[i++] = 0x00;                     /* session_id пуст */

    b[i++] = 0x00; b[i++] = 0x02;      /* cipher_suites */
    b[i++] = 0x13; b[i++] = 0x01;
    b[i++] = 0x01; b[i++] = 0x00;      /* compression */

    size_t ext_at = i; i += 2;
    size_t ext_start = i;

    /* Расширение перед SNI: разбор обязан его перешагнуть. */
    b[i++] = 0x00; b[i++] = 0x2b;      /* supported_versions */
    b[i++] = 0x00; b[i++] = 0x03;
    b[i++] = 0x02; b[i++] = 0x03; b[i++] = 0x04;

    if (with_sni) {
        b[i++] = 0x00; b[i++] = 0x00;                     /* server_name */
        b[i++] = (unsigned char)((nlen + 5) >> 8);
        b[i++] = (unsigned char)(nlen + 5);
        b[i++] = (unsigned char)((nlen + 3) >> 8);        /* длина списка */
        b[i++] = (unsigned char)(nlen + 3);
        b[i++] = 0x00;                                    /* host_name */
        b[i++] = (unsigned char)(nlen >> 8);
        b[i++] = (unsigned char)nlen;
        memcpy(b + i, name, nlen); i += nlen;
    }

    size_t ext_len = i - ext_start;
    b[ext_at]     = (unsigned char)(ext_len >> 8);
    b[ext_at + 1] = (unsigned char)ext_len;

    size_t hs_len = i - body - 4;
    b[hslen_at]     = 0;
    b[hslen_at + 1] = (unsigned char)(hs_len >> 8);
    b[hslen_at + 2] = (unsigned char)hs_len;

    size_t rec_len = i - 5;
    b[reclen_at]     = (unsigned char)(rec_len >> 8);
    b[reclen_at + 1] = (unsigned char)rec_len;

    return i;
}

/* IPv4 + TCP + нагрузка. */
static size_t wrap4(unsigned char *b, const unsigned char *pay, size_t plen,
                    unsigned dport, unsigned proto, unsigned frag)
{
    size_t total = 20 + 20 + plen;

    memset(b, 0, 40);
    b[0] = 0x45;
    b[2] = (unsigned char)(total >> 8);
    b[3] = (unsigned char)total;
    b[6] = (unsigned char)(frag >> 8);
    b[7] = (unsigned char)frag;
    b[9] = (unsigned char)proto;
    b[12] = 192; b[13] = 168; b[14] = 1; b[15] = 81;   /* источник */
    b[16] = 188; b[17] = 40;  b[18] = 167; b[19] = 81; /* назначение */

    b[20] = 0xC0; b[21] = 0x00;                        /* порт источника */
    b[22] = (unsigned char)(dport >> 8);
    b[23] = (unsigned char)dport;
    b[32] = 0x50;                                      /* 20 байт заголовка */
    b[33] = 0x18;                                      /* PSH ACK */

    memcpy(b + 40, pay, plen);
    return 40 + plen;
}

/* IPv6 + TCP + нагрузка. */
static size_t wrap6(unsigned char *b, const unsigned char *pay, size_t plen,
                    unsigned dport)
{
    memset(b, 0, 60);
    b[0] = 0x60;
    b[4] = (unsigned char)((20 + plen) >> 8);
    b[5] = (unsigned char)(20 + plen);
    b[6] = 6;                                          /* TCP */
    b[7] = 64;
    b[8]  = 0x20; b[9] = 0x01;                         /* источник */
    b[24] = 0x2a; b[25] = 0x00;                        /* назначение */

    b[40] = 0xC0; b[41] = 0x00;
    b[42] = (unsigned char)(dport >> 8);
    b[43] = (unsigned char)dport;
    b[52] = 0x50;
    b[53] = 0x18;

    memcpy(b + 60, pay, plen);
    return 60 + plen;
}

/* ---- проверки разбора ---- */

static void test_ipv4_hello(void)
{
    unsigned char hello[512], pkt[1024];
    size_t hlen = make_hello(hello, "youtube.com", 1);
    size_t len  = wrap4(pkt, hello, hlen, 443, 6, 0);

    sni_hit_t hit;
    CHECK(scap_extract(pkt, len, &hit) == 0, "IPv4 ClientHello не разобран");
    CHECK(strcmp(hit.name, "youtube.com") == 0, "имя «%s»", hit.name);
    CHECK(hit.family == 4, "семейство %u", hit.family);
    CHECK(hit.dport == 443, "порт %u", hit.dport);
    CHECK(hit.dst[0] == 188 && hit.dst[3] == 81, "адрес назначения не тот");
    CHECK(hit.src[3] == 81, "адрес источника не тот");
}

static void test_ipv6_hello(void)
{
    unsigned char hello[512], pkt[1024];
    size_t hlen = make_hello(hello, "discord.com", 1);
    size_t len  = wrap6(pkt, hello, hlen, 443);

    sni_hit_t hit;
    CHECK(scap_extract(pkt, len, &hit) == 0, "IPv6 ClientHello не разобран");
    CHECK(strcmp(hit.name, "discord.com") == 0, "имя «%s»", hit.name);
    CHECK(hit.family == 6, "семейство %u", hit.family);
}

static void test_not_ours(void)
{
    unsigned char hello[512], pkt[1024];
    size_t hlen = make_hello(hello, "example.com", 1);
    sni_hit_t hit;

    size_t len = wrap4(pkt, hello, hlen, 80, 6, 0);
    CHECK(scap_extract(pkt, len, &hit) == -1, "порт 80 должен быть чужим");

    len = wrap4(pkt, hello, hlen, 443, 17, 0);
    CHECK(scap_extract(pkt, len, &hit) == -1, "UDP должен быть чужим");

    len = wrap4(pkt, hello, hlen, 443, 6, 0x0001);
    CHECK(scap_extract(pkt, len, &hit) == -1, "фрагмент должен быть чужим");

    /* Запись прикладных данных, а не handshake. */
    hello[0] = 0x17;
    len = wrap4(pkt, hello, hlen, 443, 6, 0);
    CHECK(scap_extract(pkt, len, &hit) == -1, "не handshake — чужой");
}

static void test_no_sni(void)
{
    unsigned char hello[512], pkt[1024];
    size_t hlen = make_hello(hello, NULL, 0);
    size_t len  = wrap4(pkt, hello, hlen, 443, 6, 0);

    sni_hit_t hit;
    CHECK(scap_extract(pkt, len, &hit) == -2,
          "ClientHello без server_name — это -2, а не успех");
}

/* Обрыв на каждой длине: разбор не должен ни принять мусор, ни выйти
   за буфер. Полагаться тут на «в жизни так не бывает» нельзя —
   содержимое пакета целиком задаёт клиент. */
static void test_truncated(void)
{
    unsigned char hello[512], pkt[1024];
    size_t hlen = make_hello(hello, "youtube.com", 1);
    size_t full = wrap4(pkt, hello, hlen, 443, 6, 0);

    for (size_t cut = 1; cut < full; cut++) {
        sni_hit_t hit;
        int r = scap_extract(pkt, cut, &hit);
        CHECK(r != 0, "обрезанный до %zu пакет разобрался как целый", cut);
    }
}

static void test_bad_name(void)
{
    unsigned char hello[512], pkt[1024];
    size_t hlen = make_hello(hello, "плохое имя", 1);
    size_t len  = wrap4(pkt, hello, hlen, 443, 6, 0);

    sni_hit_t hit;
    CHECK(scap_extract(pkt, len, &hit) == -2, "имя не из доменных символов");

    hlen = make_hello(hello, "two..dots.com", 1);
    len  = wrap4(pkt, hello, hlen, 443, 6, 0);
    CHECK(scap_extract(pkt, len, &hit) == -2, "две точки подряд");

    hlen = make_hello(hello, ".leading.com", 1);
    len  = wrap4(pkt, hello, hlen, 443, 6, 0);
    CHECK(scap_extract(pkt, len, &hit) == -2, "точка в начале");
}

/* ---- проверки фильтра ядра ---- */

static void test_filter(void)
{
    unsigned char hello[512], pkt[1024];
    size_t hlen = make_hello(hello, "youtube.com", 1);

    size_t len = wrap4(pkt, hello, hlen, 443, 6, 0);
    CHECK(filter_takes(pkt, len), "фильтр не пропустил IPv4 ClientHello");

    len = wrap6(pkt, hello, hlen, 443);
    CHECK(filter_takes(pkt, len), "фильтр не пропустил IPv6 ClientHello");

    len = wrap4(pkt, hello, hlen, 80, 6, 0);
    CHECK(!filter_takes(pkt, len), "фильтр пропустил порт 80");

    len = wrap4(pkt, hello, hlen, 443, 17, 0);
    CHECK(!filter_takes(pkt, len), "фильтр пропустил UDP");

    len = wrap4(pkt, hello, hlen, 443, 6, 0x0001);
    CHECK(!filter_takes(pkt, len), "фильтр пропустил фрагмент");

    /* Прикладные данные — их на соединение тысячи, и именно ради них
       проверка нагрузки в фильтре и нужна. */
    hello[0] = 0x17;
    len = wrap4(pkt, hello, hlen, 443, 6, 0);
    CHECK(!filter_takes(pkt, len), "фильтр пропустил прикладные данные");

    len = wrap6(pkt, hello, hlen, 443);
    CHECK(!filter_takes(pkt, len), "фильтр пропустил прикладные данные IPv6");

    /* Handshake, но не ClientHello: например ответ сервера. */
    hello[0] = 0x16; hello[5] = 0x02;
    len = wrap4(pkt, hello, hlen, 443, 6, 0);
    CHECK(!filter_takes(pkt, len), "фильтр пропустил не ClientHello");

    len = wrap6(pkt, hello, hlen, 443);
    CHECK(!filter_takes(pkt, len), "фильтр пропустил не ClientHello IPv6");

    /* Пустая квитанция без нагрузки: самый частый пакет на 443. */
    len = wrap4(pkt, hello, 0, 443, 6, 0);
    CHECK(!filter_takes(pkt, len), "фильтр пропустил пустую квитанцию");
}

/* Заголовок TCP с опциями: начало нагрузки смещается, и фильтр обязан
   считать его, а не полагаться на 20 байт. */
static void test_filter_tcp_options(void)
{
    unsigned char hello[512], pkt[1024];
    size_t hlen = make_hello(hello, "youtube.com", 1);
    size_t len  = wrap4(pkt, hello, hlen, 443, 6, 0);

    /* Раздвигаем заголовок TCP на 12 байт опций. */
    unsigned char big[1024];
    memcpy(big, pkt, 40);
    memset(big + 40, 0x01, 12);              /* NOP */
    memcpy(big + 52, pkt + 40, len - 40);
    big[32] = 0x80;                          /* 32 байта заголовка */

    size_t blen = len + 12;

    CHECK(filter_takes(big, blen), "фильтр не учёл опции TCP");

    sni_hit_t hit;
    CHECK(scap_extract(big, blen, &hit) == 0, "разбор не учёл опции TCP");
    CHECK(strcmp(hit.name, "youtube.com") == 0, "имя «%s»", hit.name);
}

static void test_open_reports_platform(void)
{
    scap_t c;
    char   err[128] = "";

    scap_init(&c);
    CHECK(c.fd == -1, "после init сокет должен быть закрыт");

    int rc = scap_open(&c, "нет-такого-интерфейса", err, sizeof(err));
    CHECK(rc == -1, "открытие на несуществующем интерфейсе обязано упасть");
    CHECK(err[0] != '\0', "причина отказа должна быть названа");

    scap_close(&c);
}

int main(void)
{
    printf("check_snicap %s\n", VERSION);

    test_ipv4_hello();
    test_ipv6_hello();
    test_not_ours();
    test_no_sni();
    test_truncated();
    test_bad_name();

    test_filter();
    test_filter_tcp_options();
    test_open_reports_platform();

    if (failures) {
        printf("ПРОВАЛЕНО проверок: %d\n", failures);
        return 1;
    }
    printf("все проверки пройдены\n");
    return 0;
}
