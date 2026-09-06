#include "proc.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

int proc_run(char *const argv[], char *out, size_t out_size, int timeout_sec)
{
    if (!argv || !argv[0]) return -1;
    if (out && out_size) out[0] = '\0';

    int pipefd[2];
    if (pipe(pipefd) != 0) return -1;

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (pid == 0) {
        /* Потомок: оба потока вывода в трубу, чтобы не потерять причину
           отказа — xray пишет диагностику и туда, и туда. */
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        if (pipefd[1] > STDERR_FILENO) close(pipefd[1]);

        int null = open("/dev/null", O_RDONLY);
        if (null >= 0) {
            dup2(null, STDIN_FILENO);
            if (null > STDERR_FILENO) close(null);
        }

        execv(argv[0], argv);
        _exit(127);                 /* execv вернулся — значит не запустился */
    }

    close(pipefd[1]);

    /* Читаем неблокирующе, чтобы таймаут работал даже когда потомок
       молчит и не закрывает трубу. */
    int flags = fcntl(pipefd[0], F_GETFL, 0);
    fcntl(pipefd[0], F_SETFL, flags | O_NONBLOCK);

    size_t len      = 0;
    time_t deadline = time(NULL) + (timeout_sec > 0 ? timeout_sec : 0);
    int    status   = 0;
    int    killed   = 0;

    for (;;) {
        char   buf[512];
        ssize_t n = read(pipefd[0], buf, sizeof(buf));

        if (n > 0) {
            if (out && out_size && len + (size_t)n < out_size) {
                memcpy(out + len, buf, (size_t)n);
                len += (size_t)n;
                out[len] = '\0';
            }
            continue;
        }

        if (n == 0) break;                       /* труба закрыта */
        if (errno != EAGAIN && errno != EWOULDBLOCK) break;

        pid_t done = waitpid(pid, &status, WNOHANG);
        if (done == pid) {
            pid = -1;
            break;
        }

        if (timeout_sec > 0 && time(NULL) >= deadline) {
            kill(pid, SIGKILL);
            killed = 1;
            break;
        }

        struct timespec ts = { 0, 50 * 1000 * 1000 };   /* 50 мс */
        nanosleep(&ts, NULL);
    }

    close(pipefd[0]);

    if (pid > 0) waitpid(pid, &status, 0);

    if (killed) return 128 + SIGKILL;
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return -1;
}
