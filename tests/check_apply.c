/* Проверяет главное свойство подмены конфига: рабочий конфиг не должен
   пострадать оттого, что новый оказался плохим. Именно этого не делал
   neofit — он писал файл и перезапускал xray, что бы там ни оказалось. */
#include "apply.h"
#include "proc.h"
#include "shadowfox.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
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

static char g_dir[256];

/* Подставной xray: ведёт себя так, как велит имя, чтобы не тянуть в
   тесты настоящее ядро. */
static void make_stub(const char *name, const char *body)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", g_dir, name);

    FILE *f = fopen(path, "w");
    fprintf(f, "#!/bin/sh\n%s\n", body);
    fclose(f);
    chmod(path, 0755);
}

static void read_file(const char *path, char *out, size_t size)
{
    out[0] = '\0';
    FILE *f = fopen(path, "r");
    if (!f) return;
    size_t n = fread(out, 1, size - 1, f);
    out[n] = '\0';
    fclose(f);
}

static void test_proc_run(void)
{
    char out[256];

    make_stub("say", "echo привет; echo беда >&2; exit 3");

    char bin[512];
    snprintf(bin, sizeof(bin), "%s/say", g_dir);
    char *argv[] = { bin, NULL };

    int rc = proc_run(argv, out, sizeof(out), 5);
    CHECK(rc == 3, "код возврата пробрасывается, получено %d", rc);
    CHECK(strstr(out, "привет") != NULL, "stdout собран");
    /* Диагностика xray идёт в stderr — потерять её нельзя. */
    CHECK(strstr(out, "беда") != NULL, "stderr собран");

    char missing[] = "/нет/такого/файла";
    char *bad[] = { missing, NULL };
    CHECK(proc_run(bad, out, sizeof(out), 5) == 127,
          "несуществующая программа даёт 127");

    /* Висящий xray не должен блокировать демона навсегда. */
    make_stub("hang", "sleep 30");
    snprintf(bin, sizeof(bin), "%s/hang", g_dir);
    char *hang[] = { bin, NULL };
    int t = proc_run(hang, out, sizeof(out), 1);
    CHECK(t > 128, "зависший процесс убит по таймауту, код %d", t);
}

static void test_good_config_replaces(void)
{
    char cfg[512], out[512];
    snprintf(cfg, sizeof(cfg), "%s/config.json", g_dir);

    FILE *f = fopen(cfg, "w");
    fprintf(f, "СТАРЫЙ");
    fclose(f);

    make_stub("xray-ok", "exit 0");

    apply_opts_t o;
    memset(&o, 0, sizeof(o));
    snprintf(o.xray_bin, sizeof(o.xray_bin), "%s/xray-ok", g_dir);
    snprintf(o.config_path, sizeof(o.config_path), "%s", cfg);
    o.test_timeout = 5;

    char err[512] = "";
    CHECK(apply_config(&o, "НОВЫЙ", err, sizeof(err)) == 0,
          "принятый конфиг применён: %s", err);

    read_file(cfg, out, sizeof(out));
    CHECK(!strcmp(out, "НОВЫЙ"), "файл заменён, внутри: %s", out);

    /* uuid в конфиге — ключ доступа, посторонним он не нужен. */
    struct stat st;
    CHECK(stat(cfg, &st) == 0 && (st.st_mode & 0077) == 0,
          "права 0600, а не мир-читаемые: %o", st.st_mode & 0777);
}

static void test_bad_config_keeps_old(void)
{
    char cfg[512], out[512], tmp[600];
    snprintf(cfg, sizeof(cfg), "%s/config2.json", g_dir);
    snprintf(tmp, sizeof(tmp), "%s.new", cfg);

    FILE *f = fopen(cfg, "w");
    fprintf(f, "РАБОЧИЙ");
    fclose(f);

    make_stub("xray-bad", "echo 'Failed to load config' >&2; exit 23");

    apply_opts_t o;
    memset(&o, 0, sizeof(o));
    snprintf(o.xray_bin, sizeof(o.xray_bin), "%s/xray-bad", g_dir);
    snprintf(o.config_path, sizeof(o.config_path), "%s", cfg);
    o.test_timeout = 5;

    char err[512] = "";
    CHECK(apply_config(&o, "МУСОР", err, sizeof(err)) == -1,
          "отвергнутый конфиг не применяется");

    read_file(cfg, out, sizeof(out));
    CHECK(!strcmp(out, "РАБОЧИЙ"), "прежний конфиг цел, внутри: %s", out);
    CHECK(access(tmp, F_OK) != 0, "временный файл убран");
    CHECK(strstr(err, "Failed to load config") != NULL,
          "причина отказа от xray видна: %s", err);
}

static void test_missing_xray(void)
{
    apply_opts_t o;
    memset(&o, 0, sizeof(o));
    snprintf(o.config_path, sizeof(o.config_path), "%s/c3.json", g_dir);
    o.test_timeout = 5;

    char err[256] = "";
    CHECK(apply_config(&o, "{}", err, sizeof(err)) == -1,
          "без xray применять нечем");
    CHECK(err[0] != '\0', "причина заполнена: %s", err);
}

int main(void)
{
    printf("check_apply " VERSION "\n");

    char tpl[] = "/tmp/shadowfox-apply-XXXXXX";
    if (!mkdtemp(tpl)) { printf("не создать временный каталог\n"); return 1; }
    snprintf(g_dir, sizeof(g_dir), "%s", tpl);

    test_proc_run();
    test_good_config_replaces();
    test_bad_config_keeps_old();
    test_missing_xray();

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", g_dir);
    if (system(cmd) != 0) printf("  (не удалось убрать %s)\n", g_dir);

    if (failures) {
        printf("ПРОВАЛЕНО проверок: %d\n", failures);
        return 1;
    }
    printf("все проверки пройдены\n");
    return 0;
}
