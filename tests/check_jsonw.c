#include "jsonw.h"
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

static void test_object(void)
{
    char   buf[256];
    json_t j;

    json_init(&j, buf, sizeof(buf));
    json_obj_open(&j);
    json_kv_str(&j, "protocol", "vless");
    json_kv_int(&j, "port", 443);
    json_kv_bool(&j, "udp", 1);
    json_obj_close(&j);

    CHECK(json_done(&j) == 0, "объект собран");
    CHECK(!strcmp(buf, "{\"protocol\":\"vless\",\"port\":443,\"udp\":true}"),
          "получено: %s", buf);
}

static void test_nesting(void)
{
    char   buf[256];
    json_t j;

    json_init(&j, buf, sizeof(buf));
    json_obj_open(&j);
    json_key(&j, "users");
    json_arr_open(&j);
    json_obj_open(&j);
    json_kv_str(&j, "id", "abc");
    json_obj_close(&j);
    json_obj_open(&j);
    json_kv_str(&j, "id", "def");
    json_obj_close(&j);
    json_arr_close(&j);
    json_obj_close(&j);

    CHECK(json_done(&j) == 0, "вложенность собрана");
    CHECK(!strcmp(buf, "{\"users\":[{\"id\":\"abc\"},{\"id\":\"def\"}]}"),
          "получено: %s", buf);
}

static void test_escaping(void)
{
    char   buf[256];
    json_t j;

    json_init(&j, buf, sizeof(buf));
    json_obj_open(&j);
    json_kv_str(&j, "tag", "он сказал \"да\"\nи ушёл\\");
    json_obj_close(&j);

    CHECK(json_done(&j) == 0, "экранирование не сломало сборку");
    CHECK(strstr(buf, "\\\"да\\\"") != NULL, "кавычки экранированы: %s", buf);
    CHECK(strstr(buf, "\\n") != NULL, "перевод строки экранирован");
    CHECK(strstr(buf, "\\\\") != NULL, "обратный слэш экранирован");
    /* Кириллица — валидный UTF-8, экранировать её не нужно и вредно:
       имена серверов в share-ссылках сплошь и рядом на русском. */
    CHECK(strstr(buf, "он сказал") != NULL, "UTF-8 остался как есть");
}

static void test_control_chars(void)
{
    char   buf[128];
    json_t j;
    char   value[] = { 'a', 0x01, 'b', '\0' };

    json_init(&j, buf, sizeof(buf));
    json_obj_open(&j);
    json_kv_str(&j, "k", value);
    json_obj_close(&j);

    CHECK(json_done(&j) == 0, "управляющий символ обработан");
    CHECK(strstr(buf, "\\u0001") != NULL, "управляющий символ экранирован: %s", buf);
}

static void test_str_list(void)
{
    char   buf[256];
    json_t j;

    json_init(&j, buf, sizeof(buf));
    json_obj_open(&j);
    json_kv_str_list(&j, "alpn", "h2,http/1.1", ',');
    json_obj_close(&j);
    CHECK(json_done(&j) == 0, "список собран");
    CHECK(!strcmp(buf, "{\"alpn\":[\"h2\",\"http/1.1\"]}"), "получено: %s", buf);

    json_init(&j, buf, sizeof(buf));
    json_obj_open(&j);
    json_kv_str_list(&j, "alpn", "", ',');
    json_obj_close(&j);
    CHECK(json_done(&j) == 0, "пустой список собран");
    CHECK(!strcmp(buf, "{\"alpn\":[]}"), "пустая строка даёт []: %s", buf);
}

static void test_overflow_is_reported(void)
{
    /* Молча обрезанный JSON — худший исход: xray получит битый конфиг
       и упадёт уже на роутере. Переполнение обязано быть видно вызывающему. */
    char   buf[16];
    json_t j;

    json_init(&j, buf, sizeof(buf));
    json_obj_open(&j);
    json_kv_str(&j, "очень-длинный-ключ", "и длинное значение");
    json_obj_close(&j);

    CHECK(json_done(&j) == -1, "переполнение отмечено ошибкой");
}

static void test_unbalanced_is_reported(void)
{
    char   buf[64];
    json_t j;

    json_init(&j, buf, sizeof(buf));
    json_obj_open(&j);
    json_kv_str(&j, "k", "v");
    /* Забыли закрыть объект. */

    CHECK(json_done(&j) == -1, "незакрытая скобка отмечена ошибкой");
}

int main(void)
{
    printf("check_jsonw " VERSION "\n");

    test_object();
    test_nesting();
    test_escaping();
    test_control_chars();
    test_str_list();
    test_overflow_is_reported();
    test_unbalanced_is_reported();

    if (failures) {
        printf("ПРОВАЛЕНО проверок: %d\n", failures);
        return 1;
    }
    printf("все проверки пройдены\n");
    return 0;
}
