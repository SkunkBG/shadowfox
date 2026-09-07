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

    /* Ссылки без fp: запасной — chrome, умолчание самого ядра. */
    xraycfg_defaults(&o);
    CHECK(node_from_link(
              "vless://d342d11e-d424-4583-b36e-524ab1f0afa4@example.com:443"
              "?type=tcp&security=tls&sni=example.com#нет-fp",
              &n, err, sizeof(err)) == 0, "разбор без fp");
    CHECK(xraycfg_build(&n, &o, cfg, sizeof(cfg)) == 0, "сборка без fp");
    CHECK(strstr(cfg, "\"fingerprint\":\"chrome\"") != NULL,
          "запасной отпечаток chrome");
}

static void test_generated_config(void)
{
    node_t n;
    char   err[128];
    char   cfg[16384];

    xraycfg_opts_t o;
    xraycfg_defaults(&o);

    CHECK(o.fragment == 1, "фрагментация по умолчанию включена");

    /* Reality: имя сервера открытое по замыслу, резать нечего, а
       dialerProxy лишил бы Vision splice. Фрагментации у такого узла
       быть не должно даже при включённой ручке. */
    CHECK(node_from_link(REALITY_LINK, &n, err, sizeof(err)) == 0, "разбор");
    CHECK(xraycfg_build(&n, &o, cfg, sizeof(cfg)) == 0, "конфиг reality");
    CHECK(strstr(cfg, "dialerProxy") == NULL, "reality без фрагментации");
    CHECK(strstr(cfg, "\"tag\":\"fragment\"") == NULL, "нет лишнего исходящего");
    CHECK(strstr(cfg, "\"noises\"") == NULL, "шума больше нет");
    CHECK(strstr(cfg, "\"access\":\"none\"") != NULL, "журнал доступа ядра выключен");

    /* Вход обязан слушать только петлю. У Xray listen по умолчанию
       0.0.0.0, и neofit его не задавал — получался открытый SOCKS5
       без авторизации на всех интерфейсах роутера. */
    CHECK(strstr(cfg, "\"listen\":\"127.0.0.1\"") != NULL,
          "socks слушает только localhost");

    CHECK(strstr(cfg, "\"fingerprint\":\"firefox\"") != NULL,
          "отпечаток взят из ссылки, а не подставлен свой");
    /* Обычный TLS: SNI открытый, тут фрагментация и нужна. */
    node_t t;
    CHECK(node_from_link(
              "vless://d342d11e-d424-4583-b36e-524ab1f0afa4@example.com:443"
              "?type=tcp&security=tls&sni=example.com&fp=firefox#tls",
              &t, err, sizeof(err)) == 0, "разбор tls");
    CHECK(xraycfg_build(&t, &o, cfg, sizeof(cfg)) == 0, "конфиг tls");
    CHECK(strstr(cfg, "\"dialerProxy\":\"fragment\"") != NULL,
          "tls идёт через фрагментирующий исходящий");
    CHECK(strstr(cfg, "\"packets\":\"tlshello\"") != NULL, "фрагментация");
    CHECK(strstr(cfg, "\"length\":\"300-500\"") != NULL, "куски покрупнее");

    /* И выключенное состояние обязано собираться: им меряют цену. */
    o.fragment = 0;
    CHECK(xraycfg_build(&t, &o, cfg, sizeof(cfg)) == 0, "tls без фрагментации");
    CHECK(strstr(cfg, "dialerProxy") == NULL, "выключено — нет ссылки");
    o.fragment = 1;
    CHECK(xraycfg_build(&n, &o, cfg, sizeof(cfg)) == 0, "reality снова");

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

/* allowInsecure из ссылки в конфиг не переносится: один параметр в
   подписке из чата снимал бы проверку сертификата целиком. */
static void test_allow_insecure_dropped(void)
{
    node_t n;
    char   err[128];
    char   cfg[16384];

    xraycfg_opts_t o;
    xraycfg_defaults(&o);

    CHECK(node_from_link(
              "vless://d342d11e-d424-4583-b36e-524ab1f0afa4@example.com:443"
              "?type=tcp&security=tls&sni=example.com&allowInsecure=1#x",
              &n, err, sizeof(err)) == 0, "разбор");
    CHECK(n.allow_insecure == 1, "просьба в ссылке замечена — для предупреждения");
    CHECK(xraycfg_build(&n, &o, cfg, sizeof(cfg)) == 0, "сборка");
    CHECK(strstr(cfg, "allowInsecure") == NULL, "allowInsecure в конфиге: есть");
}

int main(void)
{
    printf("check_node " VERSION "\n");

    test_reality_link();
    test_defaults_and_errors();
    test_generated_config();
    test_fingerprint();
    test_allow_insecure_dropped();
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
