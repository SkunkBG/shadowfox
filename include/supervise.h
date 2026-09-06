#ifndef SHADOWFOX_SUPERVISE_H
#define SHADOWFOX_SUPERVISE_H

#include <sys/types.h>
#include <time.h>

#define SV_PATH_MAX 256

typedef struct {
    char   bin[SV_PATH_MAX];
    char   config[SV_PATH_MAX];

    pid_t  pid;              /* 0 — не запущен */
    time_t started_at;
    time_t restart_after;    /* когда пробовать снова, 0 — сразу */
    int    backoff;          /* текущая пауза перед перезапуском, секунд */
    int    restarts;         /* сколько раз перезапускали за всё время */
} sv_t;

/* Минимальная и максимальная пауза между попытками. Ядро, падающее из-за
   недоступного сервера, иначе крутилось бы в цикле и грело роутер. */
#define SV_BACKOFF_MIN 1
#define SV_BACKOFF_MAX 60

/* Сколько секунд процесс должен прожить, чтобы запуск считался удачным
   и пауза сбросилась. Меньше — значит падает сразу, пауза растёт. */
#define SV_HEALTHY_AFTER 30

void sv_init(sv_t *sv, const char *bin, const char *config);

/* Запускает ядро. Возвращает 0 при успехе. */
int  sv_start(sv_t *sv);

/* Останавливает: SIGTERM, ожидание, затем SIGKILL. */
void sv_stop(sv_t *sv);

/* Вызывать из главного цикла. Подбирает завершившегося потомка и, если
   пришло время, перезапускает. Возвращает 1, если что-то изменилось. */
int  sv_tick(sv_t *sv, time_t now);

int  sv_is_running(const sv_t *sv);

#endif /* SHADOWFOX_SUPERVISE_H */
