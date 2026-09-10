/* Подписка Xray JSON: массив конфигов панели. Проверяем разбор без
   дерева: имена с \u-экранированием, куски верхнего уровня, порты из
   outbounds, и сборку конфига для ядра — свои входы и журнал, без dns
   панели, без правил с geoip/geosite, а балансировщик и наблюдатель
   на месте. Адреса и ключи здесь выдуманные. */
#include "xjson.h"
#include "xraycfg.h"
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

static const char *SUB =
"[\n"
"  {\n"
"    \"remarks\": \"\\ud83c\\udde9\\ud83c\\uddea Germany \\ud83c\\udf7a\",\n"
"    \"dns\": {\"servers\": [\"1.1.1.1\"], \"queryStrategy\": \"UseIP\"},\n"
"    \"log\": {\"loglevel\": \"info\"},\n"
"    \"burstObservatory\": {\"subjectSelector\": [\"proxy\"], \"pingConfig\": {\"destination\": \"http://www.gstatic.com/generate_204\", \"interval\": \"1m\"}},\n"
"    \"routing\": {\n"
"      \"domainStrategy\": \"IPIfNonMatch\",\n"
"      \"balancers\": [{\"tag\": \"Super_Balancer\", \"selector\": [\"proxy\"], \"strategy\": {\"type\": \"leastLoad\"}}],\n"
"      \"rules\": [\n"
"        {\"type\": \"field\", \"protocol\": [\"bittorrent\"], \"outboundTag\": \"direct\"},\n"
"        {\"type\": \"field\", \"ip\": [\"geoip:private\"], \"outboundTag\": \"direct\"},\n"
"        {\"type\": \"field\", \"domain\": [\"geosite:category-ru\", \"example.ru\"], \"outboundTag\": \"direct\"},\n"
"        {\"type\": \"field\", \"network\": \"tcp,udp\", \"balancerTag\": \"Super_Balancer\"}\n"
"      ]\n"
"    },\n"
"    \"inbounds\": [{\"tag\": \"socks\", \"port\": 10808, \"listen\": \"127.0.0.1\", \"protocol\": \"socks\"}],\n"
"    \"outbounds\": [\n"
"      {\"tag\": \"proxy\", \"protocol\": \"vless\", \"settings\": {\"vnext\": [{\"address\": \"a.example.com\", \"port\": 443, \"users\": [{\"id\": \"00000000-0000-0000-0000-000000000001\", \"flow\": \"xtls-rprx-vision\", \"encryption\": \"none\"}]}]}, \"streamSettings\": {\"network\": \"tcp\", \"security\": \"reality\", \"realitySettings\": {\"serverName\": \"x.example\", \"publicKey\": \"pk\", \"shortId\": \"ab\"}}},\n"
"      {\"tag\": \"proxy-2\", \"protocol\": \"vless\", \"settings\": {\"vnext\": [{\"address\": \"b.example.com\", \"port\": 8443, \"users\": [{\"id\": \"00000000-0000-0000-0000-000000000002\"}]}]}},\n"
"      {\"tag\": \"direct\", \"protocol\": \"freedom\"},\n"
"      {\"tag\": \"block\", \"protocol\": \"blackhole\"}\n"
"    ]\n"
"  },\n"
"  {\"remarks\": \"🇧🇬 Bulgaria\", \"outbounds\": [{\"tag\": \"proxy\", \"protocol\": \"vless\", \"settings\": {\"vnext\": [{\"address\": \"c.example.com\", \"port\": 443}]}}], \"routing\": {\"rules\": []}},\n"
"  {\"remarks\": \"broken, no outbounds\", \"routing\": {}}\n"
"]\n";

static void test_parse(void)
{
    static xjson_t x;
    int n = xjson_parse(SUB, &x);
    CHECK(n == 2, "два конфига с outbounds: %d", n);
    CHECK(x.skipped == 1, "один без outbounds пропущен: %d", x.skipped);
    CHECK(!strcmp(x.items[0].remarks, "🇩🇪 Germany 🍺"), "имя из \\u-пар: [%s]", x.items[0].remarks);
    CHECK(!strcmp(x.items[1].remarks, "🇧🇬 Bulgaria"), "имя как есть: [%s]", x.items[1].remarks);

    int ports[8];
    int np = xjson_ports(&x.items[0], ports, 8);
    CHECK(np == 2 && ports[0] == 443 && ports[1] == 8443, "порты из outbounds: %d", np);
    CHECK(xjson_ports(&x.items[1], ports, 8) == 1 && ports[0] == 443, "один порт");

    CHECK(xjson_looks_like("  [ {"), "массив");
    CHECK(xjson_looks_like("{\"a\":1}"), "объект");
    CHECK(!xjson_looks_like("vless://a@b:1"), "ссылка — не JSON");
    CHECK(!xjson_looks_like("dmxlc3M6Ly9h"), "base64 — не JSON");

    static xjson_t one;
    CHECK(xjson_parse("{\"remarks\":\"solo\",\"outbounds\":[]}", &one) == 1 &&
          !strcmp(one.items[0].remarks, "solo"), "один объект без массива");
    CHECK(xjson_parse("[{\"outbounds\":[", &one) < 0 || one.count == 0, "битый JSON не даёт конфигов");
}

/* Весь буфер — ровно одно значение JSON, без хвоста. */
static int whole_json(const char *buf)
{
    const char *end = buf + strlen(buf);
    const char *e   = xjson_skip_value(buf, end);
    return e && xjson_ws(e, end) == end;
}

static void test_compose(void)
{
    static xjson_t x;
    CHECK(xjson_parse(SUB, &x) == 2, "разбор");

    xraycfg_opts_t o;
    xraycfg_defaults(&o);
    o.listen     = "192.168.1.1";
    o.socks_port = 1301;
    o.socks_user = "shadowfox";
    o.socks_pass = "secret";
    o.error_log  = "/tmp/x.log";

    static char out[64 * 1024];
    CHECK(xraycfg_build_from_json(&x.items[0], &o, out, sizeof(out)) == 0, "сборка");
    CHECK(whole_json(out), "результат — один целый объект JSON");

    CHECK(strstr(out, "\"listen\":\"192.168.1.1\"") && strstr(out, "\"port\":1301"), "свой вход");
    CHECK(strstr(out, "\"pass\":\"secret\""), "пароль на вход");
    CHECK(strstr(out, "\"maskAddress\":\"half\""), "свой журнал");
    CHECK(!strstr(out, "\"loglevel\":\"info\""), "журнал панели выброшен");
    CHECK(!strstr(out, "queryStrategy"), "dns панели выброшен");
    CHECK(!strstr(out, "10808"), "вход панели выброшен");
    CHECK(!strstr(out, "remarks"), "remarks не уходит ядру");

    CHECK(strstr(out, "burstObservatory") && strstr(out, "generate_204"), "наблюдатель на месте");
    CHECK(strstr(out, "Super_Balancer") && strstr(out, "leastLoad"), "балансировщик на месте");
    CHECK(strstr(out, "\"proxy-2\"") && strstr(out, "b.example.com"), "все outbounds на месте");

    CHECK(!strstr(out, "geoip:private") && !strstr(out, "geosite:category-ru"),
          "правила с geo выброшены");
    CHECK(!strstr(out, "example.ru"), "правило с geosite выброшено целиком");
    CHECK(strstr(out, "bittorrent") && strstr(out, "balancerTag"), "остальные правила на месте");
    CHECK(strstr(out, "IPIfNonMatch"), "domainStrategy на месте");

    /* Второй конфиг: routing без правил, один outbound. */
    CHECK(xraycfg_build_from_json(&x.items[1], &o, out, sizeof(out)) == 0 && whole_json(out),
          "сборка простого конфига");
    CHECK(strstr(out, "c.example.com"), "outbound на месте");
}

int main(void)
{
    printf("check_xjson %s\n", VERSION);
    test_parse();
    test_compose();
    if (failures) { printf("  провалов: %d\n", failures); return 1; }
    printf("все проверки пройдены\n");
    return 0;
}
