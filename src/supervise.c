#include "supervise.h"
#include "shadowfox.h"
#include "log.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

void sv_init(sv_t *sv, const char *bin, const char *config)
{
    memset(sv, 0, sizeof(*sv));
    str_copy(sv->bin, sizeof(sv->bin), bin ? bin : "");
    str_copy(sv->config, sizeof(sv->config), config ? config : "");
    sv->backoff = SV_BACKOFF_MIN;
}

int sv_is_running(const sv_t *sv)
{
    return sv && sv->pid > 0;
}

int sv_start(sv_t *sv)
{
    if (!sv || sv->pid > 0) return 0;

    if (!sv->bin[0] || access(sv->bin, X_OK) != 0) {
        log_error("не найден исполняемый файл ядра: %s", sv->bin);
        return -1;
    }
    if (access(sv->config, R_OK) != 0) {
        log_error("не прочитать конфиг %s: %s", sv->config, strerror(errno));
        return -1;
    }

    /* Журнал ошибок ядра растёт без нас: ядро дописывает его само.
       Обрезаем не при каждом запуске — иначе после падения нечего
       читать, — а когда он перерос предел. tmpfs не резиновая. */
    struct stat lst;
    if (stat(XRAY_ERROR_LOG, &lst) == 0 && lst.st_size > XRAY_ERROR_LOG_CAP) {
        int lfd = open(XRAY_ERROR_LOG, O_WRONLY | O_TRUNC | O_NOFOLLOW);
        if (lfd >= 0) close(lfd);
    }

    pid_t pid = fork();
    if (pid < 0) {
        log_error("fork не удался: %s", strerror(errno));
        return -1;
    }

    if (pid == 0) {
        /* Своя группа процессов: убивая ядро, не заденем себя,
           и наоборот — сигнал нам не уронит ядро вслепую. */
        setsid();

        int null = open("/dev/null", O_RDWR);
        if (null >= 0) {
            dup2(null, STDIN_FILENO);
            dup2(null, STDOUT_FILENO);
            dup2(null, STDERR_FILENO);
            if (null > STDERR_FILENO) close(null);
        }

        char bin[SV_PATH_MAX];
        char cfg[SV_PATH_MAX];
        memcpy(bin, sv->bin, sizeof(bin));
        memcpy(cfg, sv->config, sizeof(cfg));

        char *argv[] = { bin, "run", "-c", cfg, NULL };
        execv(bin, argv);
        _exit(127);
    }

    sv->pid           = pid;
    sv->started_at    = time(NULL);
    sv->restart_after = 0;
    log_info("ядро запущено, pid %ld", (long)pid);
    return 0;
}

void sv_stop(sv_t *sv)
{
    if (!sv || sv->pid <= 0) return;

    pid_t pid = sv->pid;
    kill(pid, SIGTERM);

    /* Даём завершиться по-хорошему; если не желает — убиваем. */
    for (int i = 0; i < 50; i++) {
        int   status;
        pid_t done = waitpid(pid, &status, WNOHANG);
        if (done == pid) {
            sv->pid = 0;
            log_info("ядро остановлено");
            return;
        }
        struct timespec ts = { 0, 100 * 1000 * 1000 };  /* 100 мс */
        nanosleep(&ts, NULL);
    }

    log_warn("ядро не ответило на SIGTERM, убиваю");
    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
    sv->pid = 0;
}

int sv_tick(sv_t *sv, time_t now)
{
    if (!sv) return 0;

    if (sv->pid > 0) {
        int   status;
        pid_t done = waitpid(sv->pid, &status, WNOHANG);
        if (done != sv->pid) return 0;              /* всё ещё живо */

        time_t lived = now - sv->started_at;
        sv->pid      = 0;
        sv->restarts++;

        if (WIFEXITED(status))
            log_warn("ядро завершилось с кодом %d, прожив %ld с",
                     WEXITSTATUS(status), (long)lived);
        else if (WIFSIGNALED(status))
            log_warn("ядро убито сигналом %d, прожив %ld с",
                     WTERMSIG(status), (long)lived);

        if (lived >= SV_HEALTHY_AFTER) {
            /* Проработало достаточно — падение считаем случайным
               и пробуем сразу, не наказывая паузой. */
            sv->backoff = SV_BACKOFF_MIN;
        } else {
            sv->backoff *= 2;
            if (sv->backoff > SV_BACKOFF_MAX) sv->backoff = SV_BACKOFF_MAX;
        }

        sv->restart_after = now + sv->backoff;
        log_info("перезапуск через %d с", sv->backoff);
        return 1;
    }

    if (sv->restart_after && now >= sv->restart_after) {
        sv->restart_after = 0;
        sv_start(sv);
        return 1;
    }

    return 0;
}
