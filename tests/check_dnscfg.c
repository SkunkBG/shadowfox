/* Разбор running-config роутера: вышестоящие серверы DNS.

   Проверяется на настоящем выводе Keenetic Ultra. Строки вида
   «tls upstream …» лежат внутри секции dns-proxy и по виду ничем не
   отличаются от строк других секций — единственный признак принадлеж-
   ности это отступ под заголовком. Мой первый вариант искал строки,
   начинающиеся с «dns-proxy», и не показал бы ни одного сервера. */
#include "dnscfg.h"
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

static char REAL[] =
    "interface GigabitEthernet1\n"
    "    ip dhcp client dns-routes\n"
    "    ip no name-servers\n"
    "!\n"
    "interface Home\n"
    "    ip name-server 192.168.1.1\n"
    "    ip dhcp client dns-routes\n"
    "!\n"
    "service dns-proxy\n"
    "dns-proxy\n"
    "    tls upstream 8.8.8.8 sni dns.google\n"
    "    tls upstream 8.8.4.4 sni dns.google\n"
    "    tls upstream 9.9.9.9 sni dns.quad9.net\n"
    "    tls upstream 149.112.112.112 sni dns.quad9.net\n"
    "    https upstream https://dns.quad9.net/dns-query dnsm\n"
    "    https upstream https://dns.google/dns-query dnsm\n"
    "!\n"
    "system\n"
    "    hostname Keenetic\n"
    "    set net.ipv4.tcp_fin_timeout 30\n"
    "!\n";

int main(void)
{
    printf("check_dnscfg " VERSION "\n");

    char        text[sizeof(REAL)];
    const char *out[32];

    memcpy(text, REAL, sizeof(REAL));
    int n = dns_upstreams(text, out, 32);

    CHECK(n == 7, "строк найдено: %d, ждали 7", n);

    CHECK(n > 0 && !strcmp(out[0], "ip name-server 192.168.1.1"),
          "сервер интерфейса: %s", n ? out[0] : "-");
    CHECK(n > 1 && !strcmp(out[1], "tls upstream 8.8.8.8 sni dns.google"),
          "первый upstream: %s", n > 1 ? out[1] : "-");
    CHECK(n > 6 && !strcmp(out[6], "https upstream https://dns.google/dns-query dnsm"),
          "последний upstream: %s", n > 6 ? out[6] : "-");

    /* Чужого попасть не должно: строк про dhcp и про систему там полно. */
    for (int i = 0; i < n; i++) {
        CHECK(!strstr(out[i], "dhcp"), "строка про dhcp просочилась: %s", out[i]);
        CHECK(!strstr(out[i], "hostname"), "строка про систему просочилась: %s", out[i]);
        CHECK(!strstr(out[i], "no name-servers"),
              "отключённые серверы не показываем: %s", out[i]);
    }

    /* Заголовок секции сам по себе не сервер. */
    for (int i = 0; i < n; i++)
        CHECK(strcmp(out[i], "dns-proxy") != 0, "заголовок секции попал в список");

    /* Пустой и мусорный ввод не должны ничего давать. */
    char empty[] = "";
    CHECK(dns_upstreams(empty, out, 32) == 0, "пусто — ничего");

    char junk[] = "tls upstream 1.1.1.1 sni cloudflare-dns.com\n";
    CHECK(dns_upstreams(junk, out, 32) == 0,
          "строка без секции не считается: отступа нет");

    /* Ограничение по размеру обязано соблюдаться. */
    memcpy(text, REAL, sizeof(REAL));
    CHECK(dns_upstreams(text, out, 3) == 3, "больше запрошенного не вернём");

    /* Интерфейсы, у которых DNS провайдера ещё включён. */
    {
        static char cfg[] =
            "interface GigabitEthernet1\n"
            "    ip dhcp client dns-routes\n"
            "    ip no name-servers\n"
            "!\n"
            "interface GigabitEthernet2\n"
            "    ip dhcp client dns-routes\n"
            "!\n"
            "interface Home\n"
            "    ip address 192.168.1.1 255.255.255.0\n"
            "!\n"
            "interface Wireguard0\n"
            "    ip dhcp client dns-routes\n"
            "!\n"
            "system\n"
            "    hostname Keenetic\n"
            "!\n";

        char        buf[sizeof(cfg)];
        const char *ifs[8];

        memcpy(buf, cfg, sizeof(cfg));
        int k = dns_isp_interfaces(buf, ifs, 8);

        CHECK(k == 2, "интерфейсов с DNS провайдера: %d, ждали 2", k);
        CHECK(k > 0 && !strcmp(ifs[0], "GigabitEthernet2"),
              "первый: %s", k ? ifs[0] : "-");
        CHECK(k > 1 && !strcmp(ifs[1], "Wireguard0"),
              "второй: %s", k > 1 ? ifs[1] : "-");

        /* Отключённый и домашняя сеть попасть не должны. */
        for (int i = 0; i < k; i++) {
            CHECK(strcmp(ifs[i], "GigabitEthernet1") != 0, "уже отключённый попал");
            CHECK(strcmp(ifs[i], "Home") != 0, "домашняя сеть попала");
        }

        /* Последняя секция без завершителя тоже обязана учитываться. */
        static char tail[] =
            "interface GigabitEthernet9\n"
            "    ip dhcp client dns-routes\n";
        char t2[sizeof(tail)];
        memcpy(t2, tail, sizeof(tail));
        CHECK(dns_isp_interfaces(t2, ifs, 8) == 1, "последняя секция учтена");
    }

    if (failures) {
        printf("ПРОВАЛЕНО проверок: %d\n", failures);
        return 1;
    }
    printf("все проверки пройдены\n");
    return 0;
}
