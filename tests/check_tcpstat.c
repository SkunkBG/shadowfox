#include "tcpstat.h"
#include "shadowfox.h"

#include <stdio.h>
#include <string.h>

static int failures;
#define CHECK(cond, msg) do { \
    if (!(cond)) { printf("  ПРОВАЛ %s:%d: %s\n", __FILE__, __LINE__, msg); failures++; } \
} while (0)

/* Реальный формат /proc/net/tcp: заголовок, наш socks на 1301 (слушает),
   исходящее к серверу :443 установлено с 3 повторами, второе к серверу
   в SYN_SENT, чужое установленное к :443 с другим inode, наше к :80. */
static const char SAMPLE[] =
"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
"   0: 0101A8C0:0515 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001 1 0000000000000000 100 0 0 10 0\n"
"   1: 0101A8C0:C3A2 022A7B83:01BB 01 00000000:00000000 00:00000000 00000003     0        0 1002 1 0000000000000000 20 4 30 10 -1\n"
"   2: 0101A8C0:C3A3 022A7B83:01BB 02 00000001:00000000 01:00000010 00000000     0        0 1003 1 0000000000000000 20 4 30 10 -1\n"
"   3: 0101A8C0:C3A4 022A7B83:01BB 01 00000000:00000000 00:00000000 00000000     0        0 9999 1 0000000000000000 20 4 30 10 -1\n"
"   4: 0101A8C0:C3A5 0101A8C0:0050 01 00000000:00000000 00:00000000 00000000     0        0 1004 1 0000000000000000 20 4 30 10 -1\n";

static const char SAMPLE6[] =
"  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
"   0: 00000000000000000000000001000000:C3B0 0000000000000000000000000B0F0001:01BB 01 00000000:00000000 00:00000000 00000002     0        0 1005 1 0000000000000000 20 4 30 10 -1\n";

int main(void)
{
    printf("check_tcpstat " VERSION "\n");

    unsigned long ours[] = { 1001, 1002, 1003, 1004, 1005 };
    int           ports[] = { 443 };
    tcpstat_t     s;

    int n = tcpstat_parse(SAMPLE, ours, 5, ports, 1, &s);
    CHECK(n == 2, "учтены две наши строки к :443");
    CHECK(s.established == 1, "одно установленное");
    CHECK(s.syn_sent == 1, "одно в SYN_SENT");
    CHECK(s.retrans == 3, "повторы с установленного");

    n = tcpstat_parse(SAMPLE6, ours, 5, ports, 1, &s);
    CHECK(n == 1 && s.established == 1 && s.retrans == 2, "tcp6: порт берётся от конца адреса");

    unsigned long none[] = { 42 };
    n = tcpstat_parse(SAMPLE, none, 1, ports, 1, &s);
    CHECK(n == 0 && s.established == 0 && s.syn_sent == 0, "чужие inode не считаются");

    int other[] = { 8443 };
    n = tcpstat_parse(SAMPLE, ours, 5, other, 1, &s);
    CHECK(n == 0, "другой порт не считается");

    n = tcpstat_parse("", ours, 5, ports, 1, &s);
    CHECK(n == 0, "пусто");
    n = tcpstat_parse("мусор без полей\n   1: x\n", ours, 5, ports, 1, &s);
    CHECK(n == 0, "мусор не роняет разбор");

    if (failures) { printf("ПРОВАЛЕНО проверок: %d\n", failures); return 1; }
    printf("все проверки пройдены\n");
    return 0;
}
