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
    CHECK(strstr(q, "create Proxy0 hash:net family inet maxelem 262144 -exist") != NULL,
          "набор v4 для группы: %s", q);
    CHECK(strstr(q, "create Proxy0v6 hash:net family inet6 maxelem 262144 -exist") != NULL,
          "набор v6 для группы");
    CHECK(strstr(q, "create Proxy1 hash:net family inet maxelem 262144 -exist") != NULL,
          "набор второй группы");
    /* -exist делает создание идемпотентным: после перезапуска демона
       наборы уже есть, и это норма. */
    CHECK(s.queued == 4, "четыре команды на две группы, получено %u", s.queued);

    /* Со временем жизни записи стареют сами. Без него набор копит
       адреса вечно, включая давно переехавшие к другим сервисам. */
    ips_t t;
    ips_init(&t, "/не/важно");
    ips_queue_create(&t, &w, 3600);
    CHECK(strstr(ips_pending(&t), "family inet maxelem 262144 timeout 3600 -exist") != NULL,
          "время жизни попадает в создание: %s", ips_pending(&t));
    CHECK(strstr(ips_pending(&t), "family inet6 maxelem 262144 timeout 3600 -exist") != NULL,
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
    CHECK(strstr(q, "add Proxy0 142.250.74.78 -exist") != NULL,
          "адрес v4 в набор своей группы: %s", q);
    CHECK(strstr(q, "add Proxy1v6 2001:db8::1 -exist") != NULL,
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
    CHECK(strstr(q, "add Proxy0 192.0.2.0/24 -exist") != NULL,
          "подсеть v4 попала в набор: %s", q);
    CHECK(strstr(q, "add Proxy0v6 2001:db8::/32 -exist") != NULL,
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
    CHECK(strstr(got, "create Proxy0") != NULL,
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

/* Разбор `ipset list -t`. Ошибка здесь тихая и дорогая с обеих сторон:
   решим «совпадает», когда нет, — получим набор, который не принимает
   записи; решим «не совпадает», когда совпадает, — сотрём все
   накопленные адреса при каждом сохранении списка. */
static void test_headers(void)
{
    wl_t w;
    load_lists(&w);

    const char *ours4 = w.groups[0].ipset4;

    char text[2048];

    /* Время жизни совпадает — пересоздавать незачем. */
    snprintf(text, sizeof(text),
             "Name: %s\n"
             "Type: hash:net\n"
             "Header: family inet hashsize 1024 maxelem 65536 timeout 86400\n"
             "Number of entries: 78\n",
             ours4);
    CHECK(ips_headers_differ(text, &w, 86400) == 0, "совпадающее время жизни");

    /* Другое время жизни — надо пересоздать. */
    CHECK(ips_headers_differ(text, &w, 3600) == 1, "другое время жизни");

    /* Набор без времени жизни, а мы хотим с ним. */
    snprintf(text, sizeof(text),
             "Name: %s\n"
             "Header: family inet hashsize 1024 maxelem 65536\n",
             ours4);
    CHECK(ips_headers_differ(text, &w, 86400) == 1, "набор без времени жизни");
    CHECK(ips_headers_differ(text, &w, 0) == 0, "и это не расхождение, если 0");

    /* Чужие наборы не наше дело: у соседа по роутеру свои параметры. */
    CHECK(ips_headers_differ(
              "Name: чужой_набор\n"
              "Header: family inet hashsize 1024 timeout 60\n",
              &w, 86400) == 0, "чужой набор не учитывается");

    /* Пусто — значит наших наборов ещё нет, создадутся с нуля. */
    CHECK(ips_headers_differ("", &w, 86400) == 0, "пустой вывод");
    CHECK(ips_headers_differ(NULL, &w, 86400) == 1, "NULL — пересоздать");
}

/* Число записей по наборам из `ipset list -t` — для страницы. */
static void test_entry_counts(void)
{
    wl_t w;
    load_lists(&w);

    char text[1024];
    snprintf(text, sizeof(text),
             "Name: чужой\nHeader: family inet\nNumber of entries: 999\n"
             "Name: %s\nType: hash:net\nHeader: family inet timeout 86400\n"
             "Size in memory: 1\nReferences: 2\nNumber of entries: 78\n"
             "Name: %s\nHeader: family inet6\nNumber of entries: 3\n",
             w.groups[0].ipset4, w.groups[0].ipset6);

    long c4[WL_GROUPS_MAX], c6[WL_GROUPS_MAX];
    ips_entry_counts(text, &w, c4, c6);
    CHECK(c4[0] == 78, "v4 первой группы: %ld", c4[0]);
    CHECK(c6[0] == 3,  "v6 первой группы: %ld", c6[0]);
    CHECK(c4[1] == -1 && c6[1] == -1, "у второй наборов нет: %ld %ld", c4[1], c6[1]);

    ips_entry_counts(NULL, &w, c4, c6);
    CHECK(c4[0] == -1, "NULL — нет данных");
}

typedef struct { int n, g[16], f[16]; char a[16][64]; long r[16]; } members_t;
static void on_member(int group, int family, const char *addr, long remaining, void *ctx)
{
    members_t *m = ctx;
    if (m->n >= 16) return;
    m->g[m->n] = group; m->f[m->n] = family; m->r[m->n] = remaining;
    snprintf(m->a[m->n], sizeof(m->a[m->n]), "%s", addr);
    m->n++;
}

static void test_members(void)
{
    wl_t w;
    load_lists(&w);

    char text[2048];
    snprintf(text, sizeof(text),
        "Name: %s\nType: hash:net\nRevision: 7\nHeader: family inet hashsize 1024 maxelem 65536 timeout 86400\n"
        "Size in memory: 1000\nReferences: 1\nNumber of entries: 3\nMembers:\n"
        "142.250.74.14 timeout 86123\n10.0.0.0/8 timeout 86400\n142.250.74.15 timeout 5\n\n"
        "Name: %s\nType: hash:net\nHeader: family inet6 hashsize 1024 maxelem 65536\n"
        "Number of entries: 1\nMembers:\n2a00:1450:4001:82f::200e\n\n"
        "Name: chuzhoi\nType: hash:ip\nMembers:\n8.8.8.8\n\n",
        w.groups[0].ipset4, w.groups[1].ipset6);

    members_t m = {0};
    ips_members_parse(text, &w, on_member, &m);
    CHECK(m.n == 3, "две записи v4 и одна v6, подсеть и чужой набор пропущены");
    CHECK(m.g[0] == 0 && m.f[0] == 4 && !strcmp(m.a[0], "142.250.74.14") && m.r[0] == 86123,
          "первая запись с остатком времени");
    CHECK(m.g[1] == 0 && m.r[1] == 5, "вторая запись почти истекла");
    CHECK(m.g[2] == 1 && m.f[2] == 6 && !strcmp(m.a[2], "2a00:1450:4001:82f::200e") && m.r[2] == -1,
          "v6 без старения");
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
    test_headers();
    test_entry_counts();
    test_members();

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
