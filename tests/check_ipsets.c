/* Проверяет, какие именно команды уходят в ipset. Настоящий ipset на
   macOS взять неоткуда, поэтому подставляем программу-заглушку и
   смотрим, что ей подали на вход. */
#include "ipsets.h"
#include "shadowfox.h"
#include "watchlist.h"

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

static void load_lists(wl_t *w)
{
    char dpath[160], ipath[160];
    snprintf(dpath, sizeof(dpath), "%s/d.conf", g_dir);
    snprintf(ipath, sizeof(ipath), "%s/ip.list", g_dir);

    FILE *f = fopen(dpath, "w");
    fputs("[youtube]\ninterface = Proxy0\ngooglevideo.com\n"
          "[soc]\ninterface = Proxy1\nexample.net\n", f);
    fclose(f);

    f = fopen(ipath, "w");
    fputs("[youtube]\ninterface = Proxy0\n192.0.2.0/24\n2001:db8::/32\n", f);
    fclose(f);

    wl_init(w);
    wl_load_domains(w, dpath);
    wl_load_cidrs(w, ipath);
}

static void test_create_commands(void)
{
    wl_t w;
    load_lists(&w);

    ips_t s;
    ips_init(&s, "/не/важно");
    ips_queue_create(&s, &w, 0);

    const char *q = ips_pending(&s);
    /* hash:net, а не hash:ip: в наборы кладутся и подсети из ip.list. */
    CHECK(strstr(q, "create sf4_0_youtube hash:net family inet -exist") != NULL,
          "набор v4 для группы: %s", q);
    CHECK(strstr(q, "create sf6_0_youtube hash:net family inet6 -exist") != NULL,
          "набор v6 для группы");
    CHECK(strstr(q, "create sf4_1_soc hash:net family inet -exist") != NULL,
          "набор второй группы");
    /* -exist делает создание идемпотентным: после перезапуска демона
       наборы уже есть, и это норма. */
    CHECK(s.queued == 4, "четыре команды на две группы, получено %u", s.queued);

    /* Со временем жизни записи стареют сами. Без него набор копит
       адреса вечно, включая давно переехавшие к другим сервисам. */
    ips_t t;
    ips_init(&t, "/не/важно");
    ips_queue_create(&t, &w, 3600);
    CHECK(strstr(ips_pending(&t), "family inet timeout 3600 -exist") != NULL,
          "время жизни попадает в создание: %s", ips_pending(&t));
    CHECK(strstr(ips_pending(&t), "family inet6 timeout 3600 -exist") != NULL,
          "и в набор v6 тоже");
}

static void test_add_commands(void)
{
    wl_t w;
    load_lists(&w);

    ips_t s;
    ips_init(&s, "/не/важно");

    ips_queue_add(&s, &w, 0, 4, "142.250.74.78");
    ips_queue_add(&s, &w, 1, 6, "2001:db8::1");

    const char *q = ips_pending(&s);
    CHECK(strstr(q, "add sf4_0_youtube 142.250.74.78 -exist") != NULL,
          "адрес v4 в набор своей группы: %s", q);
    CHECK(strstr(q, "add sf6_1_soc 2001:db8::1 -exist") != NULL,
          "адрес v6 в набор v6");

    /* Мусор на вход не должен превращаться в команду. */
    unsigned before = s.queued;
    ips_queue_add(&s, &w, 99, 4, "1.2.3.4");
    ips_queue_add(&s, &w, 0, 5, "1.2.3.4");
    ips_queue_add(&s, &w, 0, 4, "");
    CHECK(s.queued == before, "негодные вызовы ничего не добавили");
}

static void test_cidrs_go_to_sets(void)
{
    wl_t w;
    load_lists(&w);

    ips_t s;
    ips_init(&s, "/не/важно");
    ips_queue_cidrs(&s, &w);

    const char *q = ips_pending(&s);
    CHECK(strstr(q, "add sf4_0_youtube 192.0.2.0/24 -exist") != NULL,
          "подсеть v4 попала в набор: %s", q);
    CHECK(strstr(q, "add sf6_0_youtube 2001:db8::/32 -exist") != NULL,
          "подсеть v6 попала в набор v6");
}

static void test_flush_feeds_stdin(void)
{
    wl_t w;
    load_lists(&w);

    char seen[160], bin[160];
    snprintf(seen, sizeof(seen), "%s/seen.txt", g_dir);
    snprintf(bin, sizeof(bin), "%s/ipset-ok", g_dir);

    char body[256];
    snprintf(body, sizeof(body), "cat > %s; exit 0", seen);
    make_stub("ipset-ok", body);

    ips_t s;
    ips_init(&s, bin);
    ips_queue_create(&s, &w, 0);

    char err[256] = "";
    CHECK(ips_flush(&s, err, sizeof(err)) == 0, "пачка отдана: %s", err);
    CHECK(s.used == 0 && s.queued == 0, "очередь очищена");
    CHECK(s.applied == 4, "применённое посчитано: %u", s.applied);

    /* Главное: команды дошли до программы через stdin, а не потерялись. */
    char got[1024] = "";
    FILE *f = fopen(seen, "r");
    CHECK(f != NULL, "заглушка получила ввод");
    if (f) {
        size_t n = fread(got, 1, sizeof(got) - 1, f);
        got[n] = '\0';
        fclose(f);
    }
    CHECK(strstr(got, "create sf4_0_youtube") != NULL,
          "ipset получил команды на stdin: %s", got);

    /* Пустая очередь не должна порождать процесс. */
    CHECK(ips_flush(&s, err, sizeof(err)) == 0, "пустая очередь — успех");
}

static void test_flush_reports_failure(void)
{
    wl_t w;
    load_lists(&w);

    char bin[160];
    snprintf(bin, sizeof(bin), "%s/ipset-bad", g_dir);
    make_stub("ipset-bad", "cat >/dev/null; echo 'syntax error' >&2; exit 1");

    ips_t s;
    ips_init(&s, bin);
    ips_queue_create(&s, &w, 0);

    char err[256] = "";
    CHECK(ips_flush(&s, err, sizeof(err)) == -1, "отказ замечен");
    CHECK(strstr(err, "syntax error") != NULL, "причина видна: %s", err);
    /* Очередь всё равно сброшена: копить отвергнутое значит отвергать
       и все следующие пачки. */
    CHECK(s.queued == 0 && s.used == 0, "очередь сброшена и после отказа");
    CHECK(s.applied == 0, "неприменённое не засчитано");
}

static void test_overflow_keeps_whole_lines(void)
{
    wl_t w;
    load_lists(&w);

    ips_t s;
    ips_init(&s, "/не/важно");

    /* Переполняем буфер заведомо. Оборванная на середине команда
       заставила бы ipset restore отвергнуть всю пачку целиком. */
    for (int i = 0; i < 100000 && s.overflows == 0; i++)
        ips_queue_add(&s, &w, 0, 4, "192.0.2.1");

    CHECK(s.overflows > 0, "переполнение замечено");

    const char *q = ips_pending(&s);
    size_t len = strlen(q);
    CHECK(len > 0, "что-то в очереди осталось");
    CHECK(len == 0 || q[len - 1] == '\n', "очередь кончается целой строкой");
}

int main(void)
{
    printf("check_ipsets " VERSION "\n");

    char tpl[] = "/tmp/shadowfox-ips-XXXXXX";
    if (!mkdtemp(tpl)) { printf("не создать временный каталог\n"); return 1; }
    snprintf(g_dir, sizeof(g_dir), "%s", tpl);

    test_create_commands();
    test_add_commands();
    test_cidrs_go_to_sets();
    test_flush_feeds_stdin();
    test_flush_reports_failure();
    test_overflow_keeps_whole_lines();

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
