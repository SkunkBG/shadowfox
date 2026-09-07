/* Юнит-тесты переносимых модулей. Собираются и на macOS, и на Linux:
   это единственная часть проекта, которую можно проверить без роутера. */
#include "config.h"
#include "shadowfox.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

static void test_str_trim(void)
{
    char a[] = "  hello  ";
    CHECK(!strcmp(str_trim(a), "hello"), "обрезка с двух сторон");

    char b[] = "\t\n  x\r\n";
    CHECK(!strcmp(str_trim(b), "x"), "обрезка табов и переводов строки");

    char c[] = "   ";
    CHECK(!strcmp(str_trim(c), ""), "строка из одних пробелов");

    char d[] = "no-spaces";
    CHECK(!strcmp(str_trim(d), "no-spaces"), "строка без пробелов не меняется");
}

static void test_str_copy(void)
{
    char buf[8];

    CHECK(str_copy(buf, sizeof(buf), "abc") == 0, "короткая строка влезает");
    CHECK(!strcmp(buf, "abc"), "содержимое короткой строки");

    CHECK(str_copy(buf, sizeof(buf), "0123456789") != 0, "длинная строка усечена");
    CHECK(strlen(buf) == 7, "усечённая строка ровно по буферу");
    CHECK(buf[7] == '\0', "усечённая строка завершена нулём");
}

static void test_parse_bool(void)
{
    CHECK(parse_bool("yes", 0) == 1, "yes");
    CHECK(parse_bool("ON", 0) == 1, "регистр не важен");
    CHECK(parse_bool("no", 1) == 0, "no");
    CHECK(parse_bool("0", 1) == 0, "0");
    CHECK(parse_bool("мусор", 1) == 1, "нераспознанное значение даёт default");
    CHECK(parse_bool(NULL, 1) == 1, "NULL даёт default");
    CHECK(parse_bool("", 0) == 0, "пустая строка даёт default");
}

static void test_config_set(void)
{
    config_t cfg;
    config_defaults(&cfg);

    CHECK(cfg.log_level == LOG_INFO, "уровень по умолчанию — info");
    CHECK(cfg.auto_start == 1, "autoStart по умолчанию включён");

    CHECK(config_set(&cfg, "log", "debug") == 0, "ключ log принят");
    CHECK(cfg.log_level == LOG_DEBUG, "log=debug применился");

    CHECK(config_set(&cfg, "LOG", "off") == 0, "ключ нечувствителен к регистру");
    CHECK(cfg.log_level == LOG_OFF, "log=off применился");

    CHECK(config_set(&cfg, "pidFile", "/tmp/x.pid") == 0, "ключ pidFile принят");
    CHECK(!strcmp(cfg.pid_file, "/tmp/x.pid"), "pidFile применился");

    CHECK(!strcmp(cfg.probe_url, "http://www.gstatic.com/generate_204"),
          "проверка туннеля по умолчанию включена");
    CHECK(config_set(&cfg, "tunnelProbe", "no") == 0, "ключ tunnelProbe принят");
    CHECK(cfg.probe_url[0] == '\0', "tunnelProbe=no выключает проверку");
    CHECK(config_set(&cfg, "tunnelProbe", "http://cp.cloudflare.com/") == 0, "свой адрес");
    CHECK(!strcmp(cfg.probe_url, "http://cp.cloudflare.com/"), "адрес применился");
    CHECK(config_set(&cfg, "tunnelProbe", "") == 0 && cfg.probe_url[0] == '\0',
          "пустое значение выключает");

    CHECK(config_set(&cfg, "ерунда", "1") != 0, "неизвестный ключ отвергнут");
}

static void test_config_load_file(void)
{
    config_t cfg;
    config_defaults(&cfg);

    CHECK(config_load_file(&cfg, "/tmp/shadowfox-нет-такого-файла.conf") == 0,
          "отсутствие файла — не ошибка");

    char path[] = "/tmp/shadowfox-test-XXXXXX";
    int  fd     = mkstemp(path);
    CHECK(fd >= 0, "временный файл создан");
    if (fd < 0) return;

    FILE *f = fdopen(fd, "w");
    fprintf(f,
        "# комментарий\n"
        "\n"
        "  log = debug  \n"
        "logFile=/tmp/из-файла.log\n"
        "; точка с запятой тоже комментарий\n"
        "autoStart = no\n");
    fclose(f);

    CHECK(config_load_file(&cfg, path) == 0, "корректный файл разобран");
    CHECK(cfg.log_level == LOG_DEBUG, "значение с пробелами вокруг '=' разобрано");
    CHECK(!strcmp(cfg.log_file, "/tmp/из-файла.log"), "logFile из файла");
    CHECK(cfg.auto_start == 0, "autoStart=no из файла");

    unlink(path);
}

static void test_config_write_default(void)
{
    char dir[] = "/tmp/shadowfox-gen-XXXXXX";
    CHECK(mkdtemp(dir) != NULL, "временный каталог создан");

    char path[512];
    snprintf(path, sizeof(path), "%s/shadowfox.conf", dir);

    CHECK(config_write_default(path) == 0, "конфиг по умолчанию записан");

    /* Записанный файл обязан читаться обратно без единой ошибки —
       иначе --genconfig выдаёт то, что сам же не понимает. */
    config_t cfg;
    config_defaults(&cfg);
    CHECK(config_load_file(&cfg, path) == 0, "сгенерированный конфиг читается обратно");

    unlink(path);
    rmdir(dir);
}

/* Регрессия: SIGHUP перечитывает файл, и если после этого не наложить
   флаги CLI заново, демон теряет заданный из командной строки pidFile
   и при завершении удаляет чужой путь вместо своего. */
static void test_args_survive_reload(void)
{
    char *argv[] = { "shadowfoxd", "--pidFile", "/tmp/из-cli.pid",
                     "--log", "debug", "-f", NULL };
    int   argc   = 6;

    config_t cfg;
    config_defaults(&cfg);
    CHECK(config_apply_args(&cfg, argc, argv) == 0, "флаги CLI приняты");
    CHECK(!strcmp(cfg.pid_file, "/tmp/из-cli.pid"), "pidFile из CLI");
    CHECK(cfg.log_level == LOG_DEBUG, "log из CLI");
    CHECK(cfg.foreground == 1, "-f из CLI");

    /* Имитируем перечитывание по SIGHUP: дефолты, затем файл, затем CLI. */
    config_t fresh;
    config_defaults(&fresh);
    CHECK(config_apply_args(&fresh, argc, argv) == 0, "флаги применены повторно");
    CHECK(!strcmp(fresh.pid_file, "/tmp/из-cli.pid"),
          "после перечитывания pidFile из CLI на месте");
    CHECK(fresh.foreground == 1, "после перечитывания -f на месте");

    char *bad[] = { "shadowfoxd", "--таких-ключей-нет", "1", NULL };
    config_t c2;
    config_defaults(&c2);
    CHECK(config_apply_args(&c2, 3, bad) != 0, "неизвестный флаг отвергнут");
}

static void test_file_tail(void)
{
    char path[] = "/tmp/sf-tail-XXXXXX";
    int  fd = mkstemp(path);
    CHECK(fd >= 0, "временный файл");

    char last[64];
    long lines = 99;

    CHECK(file_tail("/nonexistent/sf", last, sizeof(last), &lines) == 0, "нет файла — 0");
    CHECK(lines == 0 && last[0] == '\0', "нет файла — пусто");

    CHECK(file_tail(path, last, sizeof(last), &lines) == 1, "пустой файл есть");
    CHECK(lines == 0 && last[0] == '\0', "пустой файл — 0 строк");

    const char *body = "первая\nвторая\n\nтретья длинная";
    CHECK(write(fd, body, strlen(body)) > 0, "запись");
    CHECK(file_tail(path, last, sizeof(last), &lines) == 1, "читается");
    CHECK(lines == 3, "пустая строка не считается, хвост без \\n считается");
    CHECK(strcmp(last, "третья длинная") == 0, "последняя строка");

    /* Строка длиннее буфера чтения считается один раз. */
    char big[1500];
    memset(big, 'x', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\n';
    CHECK(write(fd, "\n", 1) == 1 && write(fd, big, sizeof(big)) > 0, "длинная строка");
    CHECK(file_tail(path, last, sizeof(last), &lines) == 1, "читается снова");
    CHECK(lines == 4, "длинная строка — одна");
    CHECK(strlen(last) == sizeof(last) - 1 && last[0] == 'x', "хвост обрезан по буферу");

    close(fd);
    unlink(path);
}

int main(void)
{
    printf("check_config " VERSION "\n");
    test_file_tail();

    test_str_trim();
    test_str_copy();
    test_parse_bool();
    test_config_set();
    test_config_load_file();
    test_config_write_default();
    test_args_survive_reload();

    if (failures) {
        printf("ПРОВАЛЕНО проверок: %d\n", failures);
        return 1;
    }
    printf("все проверки пройдены\n");
    return 0;
}
