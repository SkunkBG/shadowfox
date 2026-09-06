#include "apply.h"
#include "log.h"
#include "proc.h"
#include "util.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

/* Свою сборку ищем первой: если стоят обе, работаем со своей. */
static const char *XRAY_CANDIDATES[] = {
    "/opt/sbin/shadowfox-xray",
    "/opt/sbin/xray",
    "/opt/bin/xray",
    NULL
};

void apply_defaults(apply_opts_t *o)
{
    memset(o, 0, sizeof(*o));
    str_copy(o->config_path, sizeof(o->config_path), "/opt/etc/xray/config.json");
    o->test_timeout = 20;
    apply_find_xray(o->xray_bin, sizeof(o->xray_bin));
}

int apply_find_xray(char *dst, unsigned dst_size)
{
    if (!dst || !dst_size) return 0;
    dst[0] = '\0';

    for (int i = 0; XRAY_CANDIDATES[i]; i++) {
        if (access(XRAY_CANDIDATES[i], X_OK) == 0) {
            str_copy(dst, dst_size, XRAY_CANDIDATES[i]);
            return 1;
        }
    }
    return 0;
}

static void fail(char *err, unsigned err_size, const char *fmt, ...)
{
    if (!err || !err_size) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, err_size, fmt, ap);
    va_end(ap);
}

int apply_config(const apply_opts_t *o, const char *json,
                 char *err, unsigned err_size)
{
    if (!o || !json) return -1;

    if (!o->xray_bin[0]) {
        fail(err, err_size, "не найден исполняемый файл xray");
        return -1;
    }

    char dir[APPLY_PATH_MAX];
    str_copy(dir, sizeof(dir), o->config_path);
    char *slash = strrchr(dir, '/');
    if (slash) {
        *slash = '\0';
        if (mkdir_p(dir, 0755) != 0) {
            fail(err, err_size, "не создать каталог %s: %s", dir, strerror(errno));
            return -1;
        }
    }

    char tmp[APPLY_PATH_MAX + 8];
    snprintf(tmp, sizeof(tmp), "%s.new", o->config_path);

    /* 0600 обязательно: в конфиге лежит uuid, то есть ключ доступа
       к серверу. Читать его посторонним на роутере незачем. */
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        fail(err, err_size, "не создать %s: %s", tmp, strerror(errno));
        return -1;
    }

    size_t  len     = strlen(json);
    ssize_t written = write(fd, json, len);
    int     wr_err  = errno;
    if (close(fd) != 0 || written != (ssize_t)len) {
        unlink(tmp);
        fail(err, err_size, "не записать %s: %s", tmp, strerror(wr_err));
        return -1;
    }

    /* execv принимает char *const[], а o у нас const. Копируем путь в
       изменяемый буфер вместо того, чтобы отбрасывать const приведением:
       -Wcast-qual такое ловит, и правильно делает. */
    char bin[APPLY_PATH_MAX];
    str_copy(bin, sizeof(bin), o->xray_bin);

    char  out[2048];
    char *argv[] = { bin, "run", "-test", "-c", tmp, NULL };
    int   rc     = proc_run(argv, out, sizeof(out), o->test_timeout);

    if (rc != 0) {
        unlink(tmp);
        /* Прежний конфиг не тронут — xray продолжает работать на нём. */
        fail(err, err_size, "xray отверг конфиг (код %d): %s", rc, out);
        return -1;
    }

    /* Переименование в пределах одной файловой системы атомарно:
       либо старый конфиг, либо новый, промежуточного состояния нет. */
    if (rename(tmp, o->config_path) != 0) {
        unlink(tmp);
        fail(err, err_size, "не заменить %s: %s", o->config_path, strerror(errno));
        return -1;
    }

    return 0;
}
