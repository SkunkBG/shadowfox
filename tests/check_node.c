#include "node.h"
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

#define REALITY_LINK                                                       \
    "vless://d342d11e-d424-4583-b36e-524ab1f0afa4@example.com:443"         \
    "?type=tcp&security=reality&pbk=PUBKEY&fp=firefox&sni=www.google.com"  \
    "&sid=6ba85179&spx=%2F&flow=xtls-rprx-vision&encryption=none"          \
    "#%D0%A2%D0%B5%D1%81%D1%82"

static void test_reality_link(void)
{
    node_t n;
    char   err[128];

    CHECK(node_from_link(REALITY_LINK, &n, err, sizeof(err)) == 0,
          "ссылка reality разобрана: %s", err);
    CHECK(!strcmp(n.id, "d342d11e-d424-4583-b36e-524ab1f0afa4"), "uuid");
    CHECK(!strcmp(n.address, "example.com"), "адрес");
    CHECK(n.port == 443, "порт");
    CHECK(!strcmp(n.security, "reality"), "security");
    CHECK(!strcmp(n.public_key, "PUBKEY"), "pbk");
    CHECK(!strcmp(n.fingerprint, "firefox"), "fp взят из ссылки");
    CHECK(!strcmp(n.flow, "xtls-rprx-vision"), "flow");
    CHECK(!strcmp(n.spider_x, "/"), "spx декодирован");
    CHECK(!strcmp(n.tag, "Тест"), "имя из фрагмента");
}

static void test_defaults_and_errors(void)
{
    node_t n;
    char   err[128];

    CHECK(node_from_link("vless://uuid@host:443", &n, err, sizeof(err)) == 0,
          "минимальная ссылка");
    CHECK(!strcmp(n.network, "tcp"), "network по умолчанию tcp");
    CHECK(!strcmp(n.security, "none"), "security по умолчанию none");
    CHECK(!strcmp(n.tag, "host:443"), "имя по умолчанию host:port");

    /* SNI не подставляется из адреса: при Reality это разные вещи. */
    CHECK(n.sni[0] == '\0', "sni пуст, если его нет в ссылке");

    CHECK(node_from_link("vless://uuid@host", &n, err, sizeof(err)) != 0,
          "ссылка без порта отвергнута");
    CHECK(node_from_link("vmess://uuid@host:443", &n, err, sizeof(err)) != 0,
          "неподдерживаемая схема отвергнута");
    CHECK(node_from_link("vless://@host:443", &n, err, sizeof(err)) != 0,
          "ссылка без uuid отвергнута");
    CHECK(node_from_link("vless://uuid@host:443?security=reality",
                         &n, err, sizeof(err)) != 0,
          "reality без pbk отвергнут");
    CHECK(err[0] != '\0', "причина ошибки заполнена");
}

/* Отпечаток uTLS: три источника и строгий порядок между ними. Панели
   почти всегда проставляют fp прямо в ссылку, и без перекрытия сменить
   его было бы негде — а chrome распознают в первую очередь. */
static void test_fingerprint(void)
{
    node_t n;
    char   err[128];
    char   cfg[16384];

    xraycfg_opts_t o;
    xraycfg_defaults(&o);

    /* Из ссылки, когда перекрытия нет. */
    CHECK(node_from_link(REALITY_LINK, &n, err, sizeof(err)) == 0, "разбор");
    CHECK(xraycfg_build(&n, &o, cfg, sizeof(cfg)) == 0, "сборка");
    CHECK(strstr(cfg, "\"fingerprint\":\"firefox\"") != NULL,
          "отпечаток берётся из ссылки");

    /* Перекрытие сильнее ссылки. */
    o.fingerprint = "safari";
    CHECK(xraycfg_build(&n, &o, cfg, sizeof(cfg)) == 0, "сборка с перекрытием");
    CHECK(strstr(cfg, "\"fingerprint\":\"safari\"") != NULL,
          "перекрытие сильнее ссылки");
    CHECK(strstr(cfg, "\"fingerprint\":\"firefox\"") == NULL,
          "старого отпечатка в конфиге не остаётся");

    /* Ссылки без fp: запасной — firefox, а не chrome. */
    xraycfg_defaults(&o);
    CHECK(node_from_link(
              "vless://d342d11e-d424-4583-b36e-524ab1f0afa4@example.com:443"
              "?type=tcp&security=tls&sni=example.com#нет-fp",
              &n, err, sizeof(err)) == 0, "разбор без fp");
    CHECK(xraycfg_build(&n, &o, cfg, sizeof(cfg)) == 0, "сборка без fp");
    CHECK(strstr(cfg, "\"fingerprint\":\"firefox\"") != NULL,
          "запасной отпечаток firefox");
}

static void test_generated_config(void)
{
    node_t n;
    char   err[128];
    char   cfg[16384];

    xraycfg_opts_t o;
    xraycfg_defaults(&o);

    /* По умолчанию включены. Раньше было наоборот; решение поменялось
       после сравнения с neofit, который умирал со временем ровно без
       этих ручек. */
    CHECK(o.fragment == 1 && o.noise == 1, "по умолчанию включены");

    CHECK(node_from_link(REALITY_LINK, &n, err, sizeof(err)) == 0, "разбор");

    /* Выключенное состояние тоже обязано собираться: им меряют, во
       сколько обходится фрагментация по скорости. */
    o.fragment = 0;
    o.noise    = 0;
    CHECK(xraycfg_build(&n, &o, cfg, sizeof(cfg)) == 0, "конфиг без фрагментации");
    CHECK(strstr(cfg, "dialerProxy") == NULL, "нет ссылки на фрагментацию");
    CHECK(strstr(cfg, "\"tag\":\"fragment\"") == NULL, "нет лишнего исходящего");

    /* Шум без фрагментации: исходящий нужен, но резать ClientHello в нём
       нечего. Одно от другого не должно зависеть. */
    o.noise = 1;
    CHECK(xraycfg_build(&n, &o, cfg, sizeof(cfg)) == 0, "конфиг только с шумом");
    CHECK(strstr(cfg, "\"tag\":\"fragment\"") != NULL, "исходящий для шума есть");
    CHECK(strstr(cfg, "\"noises\"") != NULL, "шум записан");
    CHECK(strstr(cfg, "\"packets\":\"tlshello\"") == NULL,
          "фрагментации быть не должно");

    o.fragment = 1;
    o.noise    = 1;
    CHECK(xraycfg_build(&n, &o, cfg, sizeof(cfg)) == 0, "конфиг с фрагментацией");

    /* Вход обязан слушать только петлю. У Xray listen по умолчанию
       0.0.0.0, и neofit его не задавал — получался открытый SOCKS5
       без авторизации на всех интерфейсах роутера. */
    CHECK(strstr(cfg, "\"listen\":\"127.0.0.1\"") != NULL,
          "socks слушает только localhost");

    CHECK(strstr(cfg, "\"fingerprint\":\"firefox\"") != NULL,
          "отпечаток взят из ссылки, а не подставлен свой");
    CHECK(strstr(cfg, "\"dialerProxy\":\"fragment\"") != NULL,
          "трафик узла идёт через фрагментирующий исходящий");
    CHECK(strstr(cfg, "\"packets\":\"tlshello\"") != NULL, "фрагментация");
    CHECK(strstr(cfg, "\"noises\"") != NULL, "шум");

    /* alpn в ссылке не было — значит его не должно быть и в конфиге. */
    CHECK(strstr(cfg, "\"alpn\"") == NULL,
          "alpn не выдуман там, где его не задавали");


}

static void test_alpn_from_link(void)
{
    node_t n;
    char   err[128];
    char   cfg[16384];

    xraycfg_opts_t o;
    xraycfg_defaults(&o);

    CHECK(node_from_link("vless://uuid@host:443?security=tls&alpn=h3%2Ch2&fp=safari",
                         &n, err, sizeof(err)) == 0, "ссылка с alpn");
    CHECK(xraycfg_build(&n, &o, cfg, sizeof(cfg)) == 0, "конфиг собран");
    CHECK(strstr(cfg, "\"alpn\":[\"h3\",\"h2\"]") != NULL,
          "alpn перенесён из ссылки без изменений");
    CHECK(strstr(cfg, "\"fingerprint\":\"safari\"") != NULL, "отпечаток safari");
}

static void test_transports(void)
{
    node_t n;
    char   err[128];
    char   cfg[16384];

    xraycfg_opts_t o;
    xraycfg_defaults(&o);

    CHECK(node_from_link("vless://uuid@host:443?type=ws&path=%2Fabc&host=cdn.example.com",
                         &n, err, sizeof(err)) == 0, "ws-ссылка");
    CHECK(xraycfg_build(&n, &o, cfg, sizeof(cfg)) == 0, "ws-конфиг");
    CHECK(strstr(cfg, "\"wsSettings\"") != NULL, "wsSettings");
    CHECK(strstr(cfg, "\"path\":\"/abc\"") != NULL, "путь декодирован");
    CHECK(strstr(cfg, "\"host\":\"cdn.example.com\"") != NULL, "host");

    CHECK(node_from_link("vless://uuid@host:443?type=grpc&serviceName=svc",
                         &n, err, sizeof(err)) == 0, "grpc-ссылка");
    CHECK(xraycfg_build(&n, &o, cfg, sizeof(cfg)) == 0, "grpc-конфиг");
    CHECK(strstr(cfg, "\"grpcSettings\"") != NULL, "grpcSettings");
    CHECK(strstr(cfg, "\"serviceName\":\"svc\"") != NULL, "serviceName");
}

static void test_small_buffer_fails(void)
{
    node_t n;
    char   err[128];
    char   cfg[64];

    xraycfg_opts_t o;
    xraycfg_defaults(&o);

    CHECK(node_from_link(REALITY_LINK, &n, err, sizeof(err)) == 0, "разбор");
    /* Молча обрезанный конфиг дошёл бы до xray и упал уже на роутере. */
    CHECK(xraycfg_build(&n, &o, cfg, sizeof(cfg)) == -1,
          "нехватка буфера — ошибка, а не обрезка");
}

int main(void)
{
    printf("check_node " VERSION "\n");

    test_reality_link();
    test_defaults_and_errors();
    test_generated_config();
    test_fingerprint();
    test_alpn_from_link();
    test_transports();
    test_small_buffer_fails();

    if (failures) {
        printf("ПРОВАЛЕНО проверок: %d\n", failures);
        return 1;
    }
    printf("все проверки пройдены\n");
    return 0;
}
