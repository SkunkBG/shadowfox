#ifndef SHADOWFOX_SIGNALS_H
#define SHADOWFOX_SIGNALS_H

#include <signal.h>

/* Флаги, взводимые обработчиками. Читать только из главного цикла. */
extern volatile sig_atomic_t g_shutdown;   /* SIGTERM, SIGINT */
extern volatile sig_atomic_t g_reload;     /* SIGHUP  — перечитать конфиг */
extern volatile sig_atomic_t g_restore;    /* SIGUSR1 — восстановить правила */

void signals_install(void);

#endif /* SHADOWFOX_SIGNALS_H */
