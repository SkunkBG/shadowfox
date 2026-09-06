#include "shadowfox.h"
#include "watchlist.h"

#include <arpa/inet.h>
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

static char g_dir[96];

static void write_file(const char *name, const char *body)
{
    char path[160];
    snprintf(path, sizeof(path), "%s/%s", g_dir, name);
    FILE *f = fopen(path, "w");
    fputs(body, f);
    fclose(f);
}

static void load_domains(wl_t *w, const char *body)
{
    write_file("d.conf", body);
    char path[160];
    snprintf(path, sizeof(path), "%s/d.conf", g_dir);
    wl_init(w);
    CHECK(wl_load_domains(w, path) == 0, "файл доменов прочитан");
}

static int match(const wl_t *w, const char *host)
{
    return wl_match_domain(w, host);
}

static void test_groups_and_naming(void)
{
    wl_t w;
    load_domains(&w,
        "# комментарий\n"
        "[youtube]\n"
        "interface = Proxy0\n"
        "googlevideo.com\n"
        "\n"
        "[Соцсети]\n"
        "interface = Proxy1\n"
        "example.net\n");

    CHECK(w.group_count == 2, "две группы");
    CHECK(!strcmp(w.groups[0].name, "youtube"), "имя первой группы");
    CHECK(!strcmp(w.groups[0].iface, "Proxy0"), "интерфейс первой группы");
    CHECK(!strcmp(w.groups[1].iface, "Proxy1"), "интерфейс второй группы");

    CHECK(!strcmp(w.groups[0].ipset4, "sf4_0_youtube"), "имя набора v4: %s",
          w.groups[0].ipset4);
    CHECK(!strcmp(w.groups[0].ipset6, "sf6_0_youtube"), "имя набора v6: %s",
          w.groups[0].ipset6);

    /* ipset не примет кириллицу — посторонние символы заменяются. */
    CHECK(strspn(w.groups[1].ipset4, "abcdefghijklmnopqrstuvwxyz0123456789_")
              == strlen(w.groups[1].ipset4),
          "в имени набора только допустимые символы: %s", w.groups[1].ipset4);
    CHECK(strlen(w.groups[1].ipset4) < WL_SETNAME_MAX, "имя набора влезает");
    /* Многобайтные символы не должны превращаться в вереницу
       подчёркиваний. */
    CHECK(strstr(w.groups[1].ipset4, "__") == NULL,
          "подчёркивания схлопнуты: %s", w.groups[1].ipset4);

    /* Метки и таблицы не должны пересекаться с hrneo: он берёт метки от
       12289 и таблицы от 301. */
    CHECK(w.groups[0].mark == 0x53460000u, "метка первой группы: %08x",
          w.groups[0].mark);
    CHECK(w.groups[1].mark == 0x53470000u, "метки различаются");
    /* Младшая половина метки должна оставаться свободной: там живёт
       hrneo со своими 12289 и всё, что ещё метит пакеты. */
    CHECK((w.groups[0].mark & ~WL_MARK_MASK) == 0,
          "младшая половина метки не занята");
    CHECK((w.groups[1].mark & ~WL_MARK_MASK) == 0,
          "и у второй группы тоже");
    CHECK((12289u & WL_MARK_MASK) == 0,
          "метки hrneo целиком вне нашей маски");
    CHECK(w.groups[0].table == WL_TABLE_BASE, "таблица первой группы");
    CHECK(w.groups[1].table == WL_TABLE_BASE + 1, "таблицы различаются");
    CHECK(w.groups[0].table > 301 + 256, "таблица далеко от диапазона hrneo");
}

/* Две группы, чьи имена целиком состоят из символов, недопустимых для
   ipset. При наивной очистке они дали бы одно и то же имя набора, и
   трафик одной молча уехал бы в другую. */
static void test_set_names_are_unique(void)
{
    wl_t w;
    load_domains(&w,
        "[Кино]\n"
        "interface = Proxy0\n"
        "a.com\n"
        "[Музыка]\n"
        "interface = Proxy1\n"
        "b.com\n");

    CHECK(w.group_count == 2, "две группы");
    CHECK(strcmp(w.groups[0].ipset4, w.groups[1].ipset4) != 0,
          "имена наборов v4 различаются: %s и %s",
          w.groups[0].ipset4, w.groups[1].ipset4);
    CHECK(strcmp(w.groups[0].ipset6, w.groups[1].ipset6) != 0,
          "имена наборов v6 различаются");
    CHECK(strcmp(w.groups[0].ipset4, w.groups[0].ipset6) != 0,
          "наборы v4 и v6 одной группы тоже различаются");
}

static void test_domain_kinds(void)
{
    wl_t w;
    load_domains(&w,
        "[g]\n"
        "interface = Proxy0\n"
        "example.com\n"
        "*.wild.net\n"
        "=exact.org\n");

    /* Обычная запись — сам домен и поддомены. */
    CHECK(match(&w, "example.com") == 0, "сам домен");
    CHECK(match(&w, "sub.example.com") == 0, "поддомен");
    CHECK(match(&w, "a.b.example.com") == 0, "глубокий поддомен");
    CHECK(match(&w, "EXAMPLE.COM") == 0, "регистр не важен");
    CHECK(match(&w, "example.com.") == 0, "точка на конце не мешает");

    /* Не должно цеплять чужое. */
    CHECK(match(&w, "notexample.com") == -1, "не подстрока");
    CHECK(match(&w, "example.com.evil.net") == -1, "не поддомен наоборот");
    CHECK(match(&w, "com") == -1, "родительский домен не цепляется");

    /* Маска — только поддомены. */
    CHECK(match(&w, "a.wild.net") == 0, "поддомен по маске");
    CHECK(match(&w, "wild.net") == -1, "сам домен под маску не подходит");

    /* Точное совпадение. */
    CHECK(match(&w, "exact.org") == 0, "точное совпадение");
    CHECK(match(&w, "sub.exact.org") == -1, "поддомен при точном не подходит");
}

static void test_longest_match_wins(void)
{
    /* Общее правило в первой группе, точное — во второй. Порядок строк
       не должен решать: выигрывать обязано более длинное совпадение. */
    wl_t w;
    load_domains(&w,
        "[общая]\n"
        "interface = Proxy0\n"
        "example.com\n"
        "\n"
        "[точная]\n"
        "interface = Proxy1\n"
        "cdn.example.com\n");

    CHECK(match(&w, "other.example.com") == 0, "общее правило");
    CHECK(match(&w, "cdn.example.com") == 1, "точное перекрывает общее");
    CHECK(match(&w, "a.cdn.example.com") == 1, "и его поддомены тоже");
}

static void test_bad_lines_are_skipped(void)
{
    wl_t w;
    load_domains(&w,
        "домен вне группы\n"
        "[g]\n"
        "interface = Proxy0\n"
        "ok.com\n"
        "две записи в строке\n"
        "\n");

    CHECK(w.domain_count == 1, "разобрана одна запись, а не мусор");
    /* Одна опечатка не должна обнулять список из тысячи строк. */
    CHECK(w.skipped == 2, "битые строки посчитаны: %d", w.skipped);
    CHECK(match(&w, "ok.com") == 0, "годная запись работает");
}

static void test_cidrs(void)
{
    write_file("ip.list",
        "[g]\n"
        "interface = Proxy0\n"
        "192.0.2.0/24\n"
        "198.51.100.7\n"
        "2001:db8::/32\n"
        "не подсеть\n"
        "10.0.0.0/33\n");

    char path[160];
    snprintf(path, sizeof(path), "%s/ip.list", g_dir);

    wl_t w;
    wl_init(&w);
    CHECK(wl_load_cidrs(&w, path) == 0, "файл подсетей прочитан");
    CHECK(w.cidr_count == 3, "три записи, получено %d", w.cidr_count);
    CHECK(w.skipped == 2, "мусор и неверная маска пропущены: %d", w.skipped);

    unsigned char a[16];
    inet_pton(AF_INET, "192.0.2.5", a);
    CHECK(wl_match_ip(&w, 4, a) == 0, "адрес внутри подсети");

    inet_pton(AF_INET, "192.0.3.5", a);
    CHECK(wl_match_ip(&w, 4, a) == -1, "адрес снаружи подсети");

    /* Одиночный адрес без маски — это /32. */
    inet_pton(AF_INET, "198.51.100.7", a);
    CHECK(wl_match_ip(&w, 4, a) == 0, "одиночный адрес");
    inet_pton(AF_INET, "198.51.100.8", a);
    CHECK(wl_match_ip(&w, 4, a) == -1, "соседний адрес не цепляется");

    inet_pton(AF_INET6, "2001:db8::1", a);
    CHECK(wl_match_ip(&w, 6, a) == 0, "адрес IPv6");
    inet_pton(AF_INET6, "2001:db9::1", a);
    CHECK(wl_match_ip(&w, 6, a) == -1, "чужой IPv6");

    /* Семейства не должны путаться между собой. */
    inet_pton(AF_INET, "192.0.2.5", a);
    CHECK(wl_match_ip(&w, 6, a) == -1, "адрес v4 не ищется среди v6");
}

/* Адрес, вписанный в общий список группы, обязан стать подсетью, а не
   «доменом» с таким именем: последнее не совпадает ни с чем и молчит. */
static void test_ip_in_domain_list(void)
{
    wl_t w;
    load_domains(&w,
        "[Стриминг]\n"
        "interface = ShadowFox\n"
        "netflix.com\n"
        "104.244.42.0/24\n"
        "8.8.8.8\n"
        "2001:db8::/32\n");

    CHECK(w.domain_count == 1, "доменов ровно один: %d", w.domain_count);
    CHECK(w.cidr_count == 3, "адресов три: %d", w.cidr_count);
    CHECK(w.skipped == 0, "ничего не отброшено: %d", w.skipped);

    unsigned char v4[4] = { 104, 244, 42, 7 };
    CHECK(wl_match_ip(&w, 4, v4) == 0, "адрес из подсети совпал");

    unsigned char dns[4] = { 8, 8, 8, 8 };
    CHECK(wl_match_ip(&w, 4, dns) == 0, "одиночный адрес совпал");

    CHECK(match(&w, "netflix.com") == 0, "домен рядом не пострадал");
    CHECK(match(&w, "104.244.42.0/24") < 0, "адрес не стал доменом");
}

/* Имя с цифрами в начале — всё ещё домен, а не адрес. */
static void test_numeric_domain_stays_domain(void)
{
    wl_t w;
    load_domains(&w,
        "[Разное]\n"
        "interface = ShadowFox\n"
        "1337x.to\n"
        "2ip.ru\n");

    CHECK(w.domain_count == 2, "оба остались доменами: %d", w.domain_count);
    CHECK(w.cidr_count == 0, "подсетей нет: %d", w.cidr_count);
    CHECK(match(&w, "1337x.to") == 0, "домен с цифр совпадает");
}

/* Выключенная группа не совпадает ни с чем — ни доменом, ни адресом,
   — но из списка не исчезает: включить её обратно надо тем же щелчком. */
static void test_disabled_group(void)
{
    wl_t w;
    load_domains(&w,
        "[Включена]\n"
        "interface = ShadowFox\n"
        "on.example\n"
        "10.0.0.0/8\n"
        "\n"
        "[Выключена]\n"
        "interface = ShadowFox\n"
        "enabled = no\n"
        "off.example\n"
        "172.16.0.0/12\n");

    CHECK(w.group_count == 2, "групп две: %d", w.group_count);
    CHECK(w.groups[0].enabled == 1, "первая включена");
    CHECK(w.groups[1].enabled == 0, "вторая выключена");
    CHECK(w.skipped == 0, "ничего не отброшено: %d", w.skipped);

    CHECK(match(&w, "on.example") == 0, "включённая совпадает");
    CHECK(match(&w, "off.example") == -1, "выключенная не совпадает");
    CHECK(match(&w, "sub.off.example") == -1, "и её поддомены тоже");

    unsigned char a[4] = { 10, 1, 2, 3 };
    CHECK(wl_match_ip(&w, 4, a) == 0, "адрес включённой совпадает");

    unsigned char b[4] = { 172, 16, 0, 1 };
    CHECK(wl_match_ip(&w, 4, b) == -1, "адрес выключенной не совпадает");

    /* Записи никуда не делись: страница их показывает и правит. */
    CHECK(w.domain_count == 2, "домены на месте: %d", w.domain_count);
    CHECK(w.cidr_count == 2, "подсети на месте: %d", w.cidr_count);
}

/* Разбор ключей не должен портить строку. Проверка ключа «enabled»
   затирала пробел перед '=' и не возвращала его, после чего «interface»
   в той же строке уже не находился. Ошибка была тихой: группа просто
   оставалась без цели. */
static void test_settings_survive_probing(void)
{
    wl_t w;
    load_domains(&w,
        "[g]\n"
        "interface = Proxy0\n"
        "enabled = yes\n"
        "x.example\n");

    CHECK(!strcmp(w.groups[0].iface, "Proxy0"),
          "интерфейс разобран после чужого ключа: «%s»", w.groups[0].iface);
    CHECK(w.groups[0].enabled == 1, "и включённость тоже");

    /* Обратный порядок ключей обязан давать то же самое. */
    wl_t v;
    load_domains(&v,
        "[g]\n"
        "enabled = no\n"
        "interface = Proxy0\n"
        "x.example\n");

    CHECK(!strcmp(v.groups[0].iface, "Proxy0"), "порядок ключей не важен");
    CHECK(v.groups[0].enabled == 0, "выключение прочитано");
}

static void test_longest_prefix_wins(void)
{
    write_file("ip2.list",
        "[широкая]\n"
        "interface = Proxy0\n"
        "10.0.0.0/8\n"
        "[узкая]\n"
        "interface = Proxy1\n"
        "10.1.2.0/24\n");

    char path[160];
    snprintf(path, sizeof(path), "%s/ip2.list", g_dir);

    wl_t w;
    wl_init(&w);
    CHECK(wl_load_cidrs(&w, path) == 0, "прочитано");

    unsigned char a[16];
    inet_pton(AF_INET, "10.9.9.9", a);
    CHECK(wl_match_ip(&w, 4, a) == 0, "широкая подсеть");
    inet_pton(AF_INET, "10.1.2.3", a);
    CHECK(wl_match_ip(&w, 4, a) == 1, "узкая перекрывает широкую");
}

static void test_missing_file(void)
{
    wl_t w;
    wl_init(&w);
    /* Нет файла — значит списков нет. Это штатная ситуация, а не сбой. */
    CHECK(wl_load_domains(&w, "/нет/такого/файла.conf") == 0,
          "отсутствие файла не ошибка");
    CHECK(w.domain_count == 0, "и записей нет");
    CHECK(wl_match_domain(&w, "example.com") == -1, "пустой список не совпадает");
}

int main(void)
{
    printf("check_watchlist " VERSION "\n");

    char tpl[] = "/tmp/shadowfox-wl-XXXXXX";
    if (!mkdtemp(tpl)) { printf("не создать временный каталог\n"); return 1; }
    snprintf(g_dir, sizeof(g_dir), "%s", tpl);

    test_groups_and_naming();
    test_set_names_are_unique();
    test_domain_kinds();
    test_longest_match_wins();
    test_bad_lines_are_skipped();
    test_cidrs();
    test_disabled_group();
    test_settings_survive_probing();
    test_ip_in_domain_list();
    test_numeric_domain_stays_domain();
    test_longest_prefix_wins();
    test_missing_file();

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
