#include "subs.h"
#include "base64.h"
#include "config.h"
#include "proc.h"
#include "shadowfox.h"
#include "util.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int subs_is_url(const char *line)
{
    if (!line) return 0;
    /* Только https: по http адрес подписки и ключи серверов ушли бы
       провайдеру открытым текстом. file:// — для проверок без сети; в
       бою файл ссылок читает root, и такое чтение ничего не открывает. */
    return !strncmp(line, "https://", 8) || !strncmp(line, "file://", 7);
}

void subs_host(const char *url, char *dst, size_t size)
{
    if (!dst || !size) return;
    dst[0] = '\0';
    const char *p = url ? strstr(url, "://") : NULL;
    if (!p) return;
    p += 3;
    size_t n = strcspn(p, "/?#");
    if (n >= size) n = size - 1;
    memcpy(dst, p, n);
    dst[n] = '\0';
}

/* Обход строк: обрезанная копия каждой в line. */
static const char *next_line(const char *p, char *line, size_t size)
{
    const char *nl  = strchr(p, '\n');
    size_t      len = nl ? (size_t)(nl - p) : strlen(p);
    if (len < size) { memcpy(line, p, len); line[len] = '\0'; }
    else line[0] = '\0';
    return nl ? nl + 1 : p + len;
}

int subs_count_urls(const char *text)
{
    int n = 0;
    char line[2048];
    for (const char *p = text ? text : ""; *p; ) {
        p = next_line(p, line, sizeof(line));
        if (subs_is_url(str_trim(line))) n++;
    }
    return n;
}

void subs_first_host(const char *text, char *dst, size_t size)
{
    if (!dst || !size) return;
    dst[0] = '\0';
    char line[2048];
    for (const char *p = text ? text : ""; *p; ) {
        p = next_line(p, line, sizeof(line));
        const char *s = str_trim(line);
        if (subs_is_url(s)) { subs_host(s, dst, size); return; }
    }
}

/* Ответ сервера: base64 от списка ссылок либо сам список. Страница
   HTML — значит, сервер не признал нас клиентом. */
static long unwrap(char *body, size_t size, long len, char *err, size_t err_size)
{
    while (len > 0 && (body[len - 1] == '\n' || body[len - 1] == '\r' ||
                       body[len - 1] == ' '))
        body[--len] = '\0';

    const char *s = body;
    while (*s == ' ' || *s == '\n' || *s == '\r' || *s == '\t') s++;

    if (*s == '<') {
        if (err) str_copy(err, err_size, "сервер отдал страницу, а не список серверов");
        return -1;
    }
    if (!*s) {
        if (err) str_copy(err, err_size, "сервер отдал пустой ответ");
        return -1;
    }
    if (strstr(s, "://")) return len;
    /* Xray JSON: массив конфигов, разбирается отдельно (xjson.h). Ответ
       вида {"statusCode":404} тоже начинается со скобки — без outbounds
       это не подписка, а ошибка панели, и затирать ею кеш нельзя. */
    if (*s == '[' || *s == '{') {
        if (memmem(s, strlen(s), "\"outbounds\"", 11)) return len;
        if (err) str_copy(err, err_size, "панель ответила ошибкой, а не списком серверов");
        return -1;
    }

    /* Раскрытое всегда короче base64, в тот же буфер помещается. */
    static char decoded[256 * 1024];
    long n = base64_decode(s, decoded, sizeof(decoded));
    if (n > 0 && (size_t)n < size && strstr(decoded, "://")) {
        memcpy(body, decoded, (size_t)n);
        body[n] = '\0';
        return n;
    }

    if (err) str_copy(err, err_size, "в ответе сервера нет ни одной ссылки");
    return -1;
}

static char *find_bin(const char *name)
{
    static char path[64];
    const char *dirs[] = { "/opt/bin", "/opt/sbin", "/usr/bin", "/bin", NULL };
    for (int i = 0; dirs[i]; i++) {
        snprintf(path, sizeof(path), "%s/%s", dirs[i], name);
        if (access(path, X_OK) == 0) return path;
    }
    return NULL;
}

/* Значение заголовка: только печатная латиница, без кавычек и переводов
   строки — что бы ни пришло от роутера, в HTTP оно должно быть безопасно. */
static void header_value(const char *name, const char *val, const char *def,
                         char *dst, size_t size)
{
    size_t n = (size_t)snprintf(dst, size, "%s: ", name);
    const char *s = val && val[0] ? val : def;
    for (; *s && n + 1 < size; s++) {
        unsigned char c = (unsigned char)*s;
        if (c >= 0x20 && c < 0x7f && c != '"' && c != '\\') dst[n++] = (char)c;
    }
    dst[n] = '\0';
    /* пробелы в конце ни к чему */
    while (n > 0 && dst[n - 1] == ' ') dst[--n] = '\0';
}

long subs_fetch(const char *url, const subs_dev_t *dev, char *out, size_t size,
                char *err, size_t err_size)
{
    const char *hwid = dev ? dev->hwid : NULL;
    if (!url || !out || size < 2) return -1;
    out[0] = '\0';

    if (!strncmp(url, "file://", 7)) {
        FILE *f = fopen(url + 7, "r");
        if (!f) { if (err) str_copy(err, err_size, "файл не открыть"); return -1; }
        size_t got = fread(out, 1, size - 1, f);
        fclose(f);
        out[got] = '\0';
        return unwrap(out, size, (long)got, err, err_size);
    }

    /* Свой User-Agent: панели по нему выбирают формат ответа, а
       браузерный получил бы страницу. */
    char agent[64];
    snprintf(agent, sizeof(agent), "ShadowFox/%s", VERSION);

    char u[2048];
    str_copy(u, sizeof(u), url);

    /* Заголовки устройства: без x-hwid панель с лимитом устройств отдаёт
       заглушку. Остальные три — как панель покажет роутер в списке
       устройств пользователя. */
    char h_hwid[160] = "", h_os[] = "x-device-os: KeeneticOS", h_ver[96], h_model[160];
    if (hwid && hwid[0]) header_value("x-hwid", hwid, "", h_hwid, sizeof(h_hwid));
    header_value("x-ver-os",       dev ? dev->osver : NULL, "unknown",  h_ver,   sizeof(h_ver));
    header_value("x-device-model", dev ? dev->model : NULL, "Keenetic", h_model, sizeof(h_model));

    char *argv[24];
    int   n = 0;
    char a_q[] = "-q", a_T[] = "-T", a_25[] = "25", a_U[] = "-U", a_O[] = "-O",
         a_dash[] = "-", a_sS[] = "-sS", a_L[] = "-L", a_m[] = "-m", a_A[] = "-A",
         a_H[] = "-H", a_hdr[] = "--header", a_f[] = "-f",
         a_https[] = "--https-only", a_proto[] = "--proto", a_pv[] = "=https",
         a_predir[] = "--proto-redir";
    char *bin = find_bin("wget");
    /* Штатный wget прошивки без TLS; нужен именно из Entware. */
    if (bin && strncmp(bin, "/opt/", 5)) bin = NULL;
    if (bin) {
        char *v[] = { bin, a_q, a_https, a_T, a_25, a_U, agent, a_O, a_dash };
        memcpy(argv, v, sizeof(v)); n = (int)(sizeof(v) / sizeof(v[0]));
        if (h_hwid[0]) { argv[n++] = a_hdr; argv[n++] = h_hwid; }
        argv[n++] = a_hdr; argv[n++] = h_os;
        argv[n++] = a_hdr; argv[n++] = h_ver;
        argv[n++] = a_hdr; argv[n++] = h_model;
        argv[n++] = u; argv[n] = NULL;
    } else if ((bin = find_bin("curl")) != NULL) {
        char *v[] = { bin, a_sS, a_f, a_L, a_proto, a_pv, a_predir, a_pv, a_m, a_25, a_A, agent };
        memcpy(argv, v, sizeof(v)); n = (int)(sizeof(v) / sizeof(v[0]));
        if (h_hwid[0]) { argv[n++] = a_H; argv[n++] = h_hwid; }
        argv[n++] = a_H; argv[n++] = h_os;
        argv[n++] = a_H; argv[n++] = h_ver;
        argv[n++] = a_H; argv[n++] = h_model;
        argv[n++] = u; argv[n] = NULL;
    } else {
        if (err) str_copy(err, err_size, "нет wget-ssl и curl: opkg install wget-ssl ca-bundle");
        return -1;
    }

    int truncated = 0;
    int rc = proc_run_capture(argv, out, size, 40, &truncated);
    if (rc != 0) {
        /* В выводе wget может оказаться адрес — его наружу не выдаём. */
        if (err) snprintf(err, err_size, "загрузка не удалась (код %d)", rc);
        out[0] = '\0';
        return -1;
    }
    if (truncated) {
        if (err) str_copy(err, err_size, "ответ сервера слишком велик");
        out[0] = '\0';
        return -1;
    }
    return unwrap(out, size, (long)strlen(out), err, err_size);
}

static int read_cache(const char *path, char *out, size_t size)
{
    FILE *f = path ? fopen(path, "r") : NULL;
    if (!f) return 0;
    size_t got = fread(out, 1, size - 1, f);
    fclose(f);
    out[got] = '\0';
    return got > 0;
}

static void write_cache(const char *path, const char *text)
{
    if (!path) return;
    char tmp[CFG_PATH_MAX + 8];
    snprintf(tmp, sizeof(tmp), "%s.new", path);
    unlink(tmp);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) return;
    size_t len = strlen(text), off = 0;
    while (off < len) {
        ssize_t n = write(fd, text + off, len - off);
        if (n <= 0) break;
        off += (size_t)n;
    }
    close(fd);
    if (off == len) rename(tmp, path);
    else unlink(tmp);
}

static int append(char *out, size_t size, size_t *used, const char *s, size_t n)
{
    if (*used + n + 1 >= size) return -1;
    memcpy(out + *used, s, n);
    *used += n;
    out[*used] = '\0';
    return 0;
}

int subs_expand(const char *text, const char *cache_path, const subs_dev_t *dev,
                char *out, size_t size, int *from_cache,
                char *err, size_t err_size)
{
    if (!text || !out || !size) return -1;
    out[0] = '\0';
    if (from_cache) *from_cache = 0;
    if (err && err_size) err[0] = '\0';

    static char fetched[256 * 1024];   /* всё скачанное, для кеша */
    static char body[256 * 1024];
    size_t used = 0, fused = 0;
    fetched[0] = '\0';
    int urls = 0, failed = 0;

    const char *p = text;
    while (*p) {
        const char *nl  = strchr(p, '\n');
        size_t      len = nl ? (size_t)(nl - p) : strlen(p);

        char line[2048];
        if (len < sizeof(line)) {
            memcpy(line, p, len);
            line[len] = '\0';
            char *s = str_trim(line);
            if (subs_is_url(s)) {
                urls++;
                char why[160] = "";
                long n = failed ? -1 : subs_fetch(s, dev, body, sizeof(body), why, sizeof(why));
                if (n > 0) {
                    if (append(fetched, sizeof(fetched), &fused, body, (size_t)n) ||
                        append(fetched, sizeof(fetched), &fused, "\n", 1)) {
                        if (err) str_copy(err, err_size, "списки серверов не помещаются");
                        failed = 1;
                    }
                } else {
                    failed = 1;
                    if (err && !err[0] && why[0]) str_copy(err, err_size, why);
                }
                goto next;
            }
        }
        if (append(out, size, &used, p, len) || append(out, size, &used, "\n", 1))
            return -1;
next:
        if (!nl) break;
        p = nl + 1;
    }

    if (!urls) return 0;

    if (!failed) {
        write_cache(cache_path, fetched);
    } else {
        if (!read_cache(cache_path, fetched, sizeof(fetched))) {
            if (err && !err[0]) str_copy(err, err_size, "подписка не скачана, кеша нет");
            return -1;
        }
        if (from_cache) *from_cache = 1;
    }

    if (append(out, size, &used, fetched, strlen(fetched)))
        return -1;
    return urls;
}
