/* Проверяет надзор за ядром: подхват падения и растущую паузу.
   Без паузы ядро, которому недоступен сервер, крутилось бы в цикле
   перезапусков и грело роутер. */
#include "shadowfox.h"
#include "supervise.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
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

/* Заведомо короче полей sv_t (256 байт), чтобы компилятор видел
   отсутствие обрезки в snprintf ниже. */
static char g_dir[96];

static void make_stub(const char *name, const char *body)
{
    char path[160];
    snprintf(path, sizeof(path), "%s/%s", g_dir, name);

    FILE *f = fopen(path, "w");
    fprintf(f, "#!/bin/sh\n%s\n", body);
    fclose(f);
    chmod(path, 0755);
}

/* Ждёт, пока потомок отработает и его подберёт sv_tick. */
static void wait_for_exit(sv_t *sv)
{
    for (int i = 0; i < 100 && sv_is_running(sv); i++) {
        struct timespec ts = { 0, 50 * 1000 * 1000 };
        nanosleep(&ts, NULL);
        sv_tick(sv, time(NULL));
    }
}

static void test_missing_binary(void)
{
    sv_t sv;
    sv_init(&sv, "/нет/такого/ядра", "/dev/null");
    CHECK(sv_start(&sv) == -1, "отсутствующее ядро не запускается");
    CHECK(!sv_is_running(&sv), "и не считается запущенным");
}

static void test_missing_config(void)
{
    char bin[160];
    make_stub("core-ok", "sleep 30");
    snprintf(bin, sizeof(bin), "%s/core-ok", g_dir);

    sv_t sv;
    sv_init(&sv, bin, "/нет/такого/конфига.json");
    /* Запускать ядро с несуществующим конфигом бессмысленно: оно тут же
       умрёт, а мы засчитаем это падением и начнём наращивать паузу. */
    CHECK(sv_start(&sv) == -1, "без конфига ядро не запускается");
}

static void test_start_and_stop(void)
{
    char bin[160], cfg[160];
    make_stub("core-live", "sleep 30");
    snprintf(bin, sizeof(bin), "%s/core-live", g_dir);
    snprintf(cfg, sizeof(cfg), "%s/core-live", g_dir);   /* просто читаемый файл */

    sv_t sv;
    sv_init(&sv, bin, cfg);
    CHECK(sv_start(&sv) == 0, "ядро запущено");
    CHECK(sv_is_running(&sv), "числится запущенным");
    CHECK(sv.pid > 0, "pid получен");

    CHECK(sv_tick(&sv, time(NULL)) == 0, "живое ядро тик не трогает");

    sv_stop(&sv);
    CHECK(!sv_is_running(&sv), "после остановки не запущено");
    CHECK(sv.pid == 0, "pid сброшен");
}

static void test_backoff_grows_then_resets(void)
{
    char bin[160], cfg[160];
    make_stub("core-dies", "exit 1");
    snprintf(bin, sizeof(bin), "%s/core-dies", g_dir);
    snprintf(cfg, sizeof(cfg), "%s/core-dies", g_dir);

    sv_t sv;
    sv_init(&sv, bin, cfg);
    CHECK(sv.backoff == SV_BACKOFF_MIN, "начальная пауза минимальна");

    CHECK(sv_start(&sv) == 0, "запуск");
    wait_for_exit(&sv);
    CHECK(!sv_is_running(&sv), "падение замечено");
    CHECK(sv.restarts == 1, "падение посчитано");
    int first = sv.backoff;
    CHECK(first > SV_BACKOFF_MIN, "пауза выросла после быстрого падения: %d", first);
    CHECK(sv.restart_after > 0, "назначено время следующей попытки");

    /* Ещё одно быстрое падение — пауза снова растёт. */
    CHECK(sv_start(&sv) == 0, "второй запуск");
    wait_for_exit(&sv);
    CHECK(sv.backoff > first, "пауза выросла ещё: %d", sv.backoff);

    /* Потолок: сколько бы ни падало, пауза не должна расти без предела. */
    for (int i = 0; i < 20; i++) {
        CHECK(sv_start(&sv) == 0, "запуск в цикле");
        wait_for_exit(&sv);
    }
    CHECK(sv.backoff <= SV_BACKOFF_MAX, "пауза упёрлась в потолок: %d", sv.backoff);

    /* А теперь притворимся, что ядро проработало достаточно долго:
       такое падение считаем случайным, и пауза обязана сброситься. */
    CHECK(sv_start(&sv) == 0, "запуск перед проверкой сброса");
    sv.started_at = time(NULL) - (SV_HEALTHY_AFTER + 5);
    wait_for_exit(&sv);
    CHECK(sv.backoff == SV_BACKOFF_MIN,
          "после долгой работы пауза сброшена, получено %d", sv.backoff);
}

static void test_restart_waits_for_backoff(void)
{
    char bin[160], cfg[160];
    make_stub("core-dies2", "exit 1");
    snprintf(bin, sizeof(bin), "%s/core-dies2", g_dir);
    snprintf(cfg, sizeof(cfg), "%s/core-dies2", g_dir);

    sv_t sv;
    sv_init(&sv, bin, cfg);
    sv_start(&sv);
    wait_for_exit(&sv);

    time_t due = sv.restart_after;
    CHECK(due > 0, "время попытки назначено");

    /* До срока перезапускать нельзя — иначе пауза не имеет смысла. */
    CHECK(sv_tick(&sv, due - 1) == 0, "раньше срока не перезапускает");
    CHECK(!sv_is_running(&sv), "и ядро всё ещё не запущено");

    CHECK(sv_tick(&sv, due) == 1, "по наступлении срока перезапускает");
    sv_stop(&sv);
}

int main(void)
{
    printf("check_supervise " VERSION "\n");

    char tpl[] = "/tmp/shadowfox-sv-XXXXXX";
    if (!mkdtemp(tpl)) { printf("не создать временный каталог\n"); return 1; }
    snprintf(g_dir, sizeof(g_dir), "%s", tpl);

    test_missing_binary();
    test_missing_config();
    test_start_and_stop();
    test_backoff_grows_then_resets();
    test_restart_waits_for_backoff();

    char cmd[160];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", g_dir);
    if (system(cmd) != 0) printf("  (не удалось убрать %s)\n", g_dir);

    if (failures) {
        printf("ПРОВАЛЕНО проверок: %d\n", failures);
        return 1;
    }
    printf("все проверки пройдены\n");
    return 0;
}
