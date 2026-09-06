#include "watchlist.h"
#include "util.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>

void wl_init(wl_t *w)
{
    memset(w, 0, sizeof(*w));
}

const char *wl_domain_text(const wl_t *w, int index)
{
    if (!w || index < 0 || index >= w->domain_count) return "";
    return w->pool + w->domains[index].offset;
}

/* Кладёт строку в пул, возвращает смещение либо -1. */
static long pool_put(wl_t *w, const char *s)
{
    size_t len = strlen(s);
    if (w->pool_used + len + 1 > sizeof(w->pool)) return -1;

    long off = (long)w->pool_used;
    memcpy(w->pool + off, s, len + 1);
    w->pool_used += (unsigned)(len + 1);
    return off;
}

/* Имя набора ipset: префикс, номер группы, затем очищенное имя.

   Номер здесь не для красоты. ipset принимает узкий набор символов, а
   имена групп бывают кириллицей — при простой замене посторонних байтов
   на подчёркивание две разные русские группы дали бы одинаковое имя, и
   трафик одной молча уехал бы в другую. Номер делает совпадение
   невозможным, а очищенный остаток нужен, чтобы имя читалось в
   `ipset list`. */
static void set_name(char *dst, size_t size, const char *prefix,
                     int index, const char *group)
{
    int n = snprintf(dst, size, "%s%d_", prefix, index);
    if (n < 0 || (size_t)n >= size) { if (size) dst[0] = '\0'; return; }

    size_t i    = (size_t)n;
    int    prev_underscore = 0;

    for (const char *g = group; *g && i + 1 < size; g++) {
        unsigned char c = (unsigned char)*g;

        if (isalnum(c)) {
            dst[i++] = (char)tolower(c);
            prev_underscore = 0;
        } else if (!prev_underscore) {
            /* Многобайтный символ не должен превращаться в вереницу
               подчёркиваний: схлопываем их в одно. */
            dst[i++] = '_';
            prev_underscore = 1;
        }
    }

    /* Подчёркивание на конце ничего не добавляет. */
    while (i > (size_t)n && dst[i - 1] == '_') i--;
    dst[i] = '\0';
}

static int group_find_or_add(wl_t *w, const char *name)
{
    for (int i = 0; i < w->group_count; i++)
        if (strcasecmp(w->groups[i].name, name) == 0) return i;

    if (w->group_count >= WL_GROUPS_MAX) return -1;

    int         idx = w->group_count++;
    wl_group_t *g   = &w->groups[idx];

    memset(g, 0, sizeof(*g));
    str_copy(g->name, sizeof(g->name), name);
    /* Префиксы sf4_ и sf6_, а не sf_ и sf6_: иначе "sf6" и номер группы
       сливаются в "sf60", что читается как группа 60 семейства v4. */
    set_name(g->ipset4, sizeof(g->ipset4), "sf4_", idx, name);
    set_name(g->ipset6, sizeof(g->ipset6), "sf6_", idx, name);
    g->mark  = WL_MARK_OF(idx);
    g->table = WL_TABLE_BASE + (unsigned)idx;
    return idx;
}

/* "[имя]" -> имя, либо NULL. */
static char *parse_header(char *s)
{
    if (*s != '[') return NULL;
    char *end = strchr(s, ']');
    if (!end) return NULL;
    *end = '\0';
    return str_trim(s + 1);
}

/* "ключ = значение" -> 1, значение в *val. */
static int parse_setting(char *s, const char *key, char **val)
{
    char *eq = strchr(s, '=');
    if (!eq) return 0;

    *eq = '\0';
    char *k = str_trim(s);
    if (strcasecmp(k, key) != 0) { *eq = '='; return 0; }

    *val = str_trim(eq + 1);
    return 1;
}

static int add_domain(wl_t *w, int group, const char *raw)
{
    if (w->domain_count >= WL_DOMAINS_MAX) return -1;

    wl_kind_t   kind = WL_NAMESPACE;
    const char *name = raw;

    if (raw[0] == '*' && raw[1] == '.') {
        kind = WL_WILDCARD;
        name = raw + 2;
    } else if (raw[0] == '=') {
        kind = WL_EXACT;
        name = raw + 1;
    }

    if (!*name || strchr(name, ' ')) return -1;

    /* Точка на конце — валидный FQDN, но сравнивать удобнее без неё. */
    char clean[256];
    if (str_copy(clean, sizeof(clean), name) != 0) return -1;
    size_t len = strlen(clean);
    while (len && clean[len - 1] == '.') clean[--len] = '\0';
    if (!len) return -1;

    for (size_t i = 0; i < len; i++)
        clean[i] = (char)tolower((unsigned char)clean[i]);

    long off = pool_put(w, clean);
    if (off < 0) return -1;

    wl_domain_t *d = &w->domains[w->domain_count++];
    d->offset = (unsigned)off;
    d->kind   = (unsigned char)kind;
    d->group  = (unsigned char)group;
    return 0;
}

static int add_cidr(wl_t *w, int group, const char *raw)
{
    if (w->cidr_count >= WL_CIDRS_MAX) return -1;

    char text[64];
    if (str_copy(text, sizeof(text), raw) != 0) return -1;

    int   prefix = -1;
    char *slash  = strchr(text, '/');
    if (slash) {
        *slash = '\0';
        char *end = NULL;
        long  p   = strtol(slash + 1, &end, 10);
        if (!end || *end || p < 0) return -1;
        prefix = (int)p;
    }

    unsigned char addr[16];
    int           family;

    if (inet_pton(AF_INET, text, addr) == 1) {
        family = 4;
        if (prefix < 0) prefix = 32;
        if (prefix > 32) return -1;
    } else if (inet_pton(AF_INET6, text, addr) == 1) {
        family = 6;
        if (prefix < 0) prefix = 128;
        if (prefix > 128) return -1;
    } else {
        return -1;
    }

    wl_cidr_t *c = &w->cidrs[w->cidr_count++];
    memcpy(c->addr, addr, family == 4 ? 4 : 16);
    if (family == 4) memset(c->addr + 4, 0, 12);
    c->family = (unsigned char)family;
    c->prefix = (unsigned char)prefix;
    c->group  = (unsigned char)group;
    return 0;
}

static int load(wl_t *w, const char *path, int cidrs)
{
    if (!w || !path) return -1;

    FILE *f = fopen(path, "r");
    if (!f) return (errno == ENOENT) ? 0 : -1;

    char line[512];
    int  group = -1;

    while (fgets(line, sizeof(line), f)) {
        char *s = str_trim(line);
        if (!*s || *s == '#' || *s == ';') continue;

        char *header = parse_header(s);
        if (header) {
            group = group_find_or_add(w, header);
            if (group < 0) w->skipped++;
            continue;
        }

        char *val = NULL;
        if (parse_setting(s, "interface", &val)) {
            if (group >= 0) str_copy(w->groups[group].iface,
                                     sizeof(w->groups[group].iface), val);
            else w->skipped++;
            continue;
        }

        /* Запись вне группы некуда отнести: без интерфейса непонятно,
           куда заворачивать трафик. */
        if (group < 0) { w->skipped++; continue; }

        int rc = cidrs ? add_cidr(w, group, s) : add_domain(w, group, s);
        if (rc != 0) w->skipped++;
    }

    fclose(f);
    return 0;
}

int wl_load_domains(wl_t *w, const char *path) { return load(w, path, 0); }
int wl_load_cidrs(wl_t *w, const char *path)   { return load(w, path, 1); }

const char *inet_ntop_prefix(const wl_cidr_t *c, char *dst, unsigned size)
{
    if (!c || !dst || size < 8) return NULL;

    char addr[INET6_ADDRSTRLEN];
    int  af = (c->family == 4) ? AF_INET : AF_INET6;

    if (!inet_ntop(af, c->addr, addr, sizeof(addr))) return NULL;

    int n = snprintf(dst, size, "%s/%u", addr, (unsigned)c->prefix);
    if (n < 0 || (unsigned)n >= size) return NULL;
    return dst;
}

int wl_match_domain(const wl_t *w, const char *host)
{
    if (!w || !host || !*host) return -1;

    char clean[256];
    if (str_copy(clean, sizeof(clean), host) != 0) return -1;

    size_t hlen = strlen(clean);
    while (hlen && clean[hlen - 1] == '.') clean[--hlen] = '\0';
    if (!hlen) return -1;

    for (size_t i = 0; i < hlen; i++)
        clean[i] = (char)tolower((unsigned char)clean[i]);

    int    best       = -1;
    size_t best_len   = 0;

    for (int i = 0; i < w->domain_count; i++) {
        const char *pat  = w->pool + w->domains[i].offset;
        size_t      plen = strlen(pat);
        int         hit  = 0;

        if (plen > hlen) continue;

        int same = (plen == hlen) && memcmp(clean, pat, plen) == 0;
        int sub  = (plen < hlen) && clean[hlen - plen - 1] == '.' &&
                   memcmp(clean + hlen - plen, pat, plen) == 0;

        switch (w->domains[i].kind) {
        case WL_EXACT:     hit = same;        break;
        case WL_WILDCARD:  hit = sub;         break;
        default:           hit = same || sub; break;
        }

        /* Выигрывает самое длинное совпадение: тогда порядок строк в
           файле не влияет, а точное правило перекрывает общее. */
        if (hit && plen > best_len) {
            best     = w->domains[i].group;
            best_len = plen;
        }
    }

    return best;
}

static int prefix_matches(const unsigned char *a, const unsigned char *b,
                          int bits)
{
    int whole = bits / 8;
    int rest  = bits % 8;

    if (whole && memcmp(a, b, (size_t)whole) != 0) return 0;
    if (rest) {
        unsigned char mask = (unsigned char)(0xFF << (8 - rest));
        if ((a[whole] & mask) != (b[whole] & mask)) return 0;
    }
    return 1;
}

int wl_match_ip(const wl_t *w, int family, const unsigned char *addr)
{
    if (!w || !addr || (family != 4 && family != 6)) return -1;

    int best     = -1;
    int best_len = -1;

    for (int i = 0; i < w->cidr_count; i++) {
        const wl_cidr_t *c = &w->cidrs[i];
        if (c->family != family) continue;
        if (!prefix_matches(addr, c->addr, c->prefix)) continue;

        if ((int)c->prefix > best_len) {
            best     = c->group;
            best_len = c->prefix;
        }
    }

    return best;
}
