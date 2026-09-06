#include "signals.h"

#include <signal.h>
#include <string.h>

volatile sig_atomic_t g_shutdown = 0;
volatile sig_atomic_t g_reload   = 0;
volatile sig_atomic_t g_restore  = 0;

static void on_signal(int sig)
{
    switch (sig) {
    case SIGTERM:
    case SIGINT:
        g_shutdown = 1;
        break;
    case SIGHUP:
        g_reload = 1;
        break;
    case SIGUSR1:
        g_restore = 1;
        break;
    default:
        break;
    }
}

void signals_install(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;

    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGHUP,  &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);

    /* Пишем в закрытый сокет — получаем EPIPE, а не смерть процесса. */
    signal(SIGPIPE, SIG_IGN);
}
