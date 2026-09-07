#ifndef SHADOWFOX_PROBE_H
#define SHADOWFOX_PROBE_H

#include <stddef.h>

/* Проверка живого туннеля.

   «Ядро работает» значит лишь, что процесс есть. Сервер может лежать,
   ключ — быть отозван, провайдер — резать соединение, а процесс при этом
   жив и здоров. Единственный честный способ узнать — пройти туннелем
   насквозь: подключиться к своему же SOCKS, попросить его соединить с
   внешним адресом и получить оттуда ответ.

   Всё неблокирующее и по шагам из главного цикла: демон однопоточный, и
   десять секунд ожидания мёртвого сервера остановили бы перехват. Идём
   по обычному HTTP, не TLS: нам нужен факт ответа, а не тайна, и свой
   TLS-клиент здесь был бы лишним кодом ради ничего. Сам туннель при
   этом зашифрован как всегда — мы лишь пассажир. */

#define PROBE_TIMEOUT   10      /* секунд на всю проверку */
#define PROBE_HOST_MAX  128
#define PROBE_PATH_MAX  128
#define PROBE_WHY_MAX   96

typedef enum {
    PROBE_IDLE = 0,
    PROBE_CONNECT,    /* ждём соединения с SOCKS */
    PROBE_GREET,      /* послали приветствие, ждём выбор метода */
    PROBE_REQUEST,    /* послали CONNECT, ждём ответ */
    PROBE_HTTP,       /* послали GET, ждём строку ответа */
    PROBE_DONE
} probe_state_t;

typedef struct {
    int           fd;
    probe_state_t state;
    long          started;             /* секунды, для срока */

    char          host[PROBE_HOST_MAX];
    int           port;
    char          path[PROBE_PATH_MAX];

    unsigned char buf[512];
    size_t        len;

    /* Итог: заполняется при переходе в PROBE_DONE. */
    int           ok;
    int           ms;                  /* от GET до первой строки ответа */
    char          why[PROBE_WHY_MAX];

    long          t0_ms;               /* монотонные миллисекунды на GET */
} probe_t;

void probe_init(probe_t *p);

/* Разбирает http://host[:port]/path. Только http: см. выше.
   Возвращает 0 при успехе. */
int  probe_parse_url(const char *url, char *host, size_t host_size,
                     int *port, char *path, size_t path_size);

/* Начинает проверку через SOCKS5 на proxy:proxy_port к url.
   Возвращает 0, если проверка пошла; -1 — ошибка сразу, why заполнен. */
int  probe_start(probe_t *p, const char *proxy, int proxy_port,
                 const char *url, long now);

/* Дескриптор для ожидания чтения в главном цикле, либо -1. */
int  probe_fd(const probe_t *p);

/* Продвигает проверку. Возвращает 1, когда она завершилась (ok/why
   заполнены), 0 — ещё идёт. После завершения сокет закрыт. */
int  probe_poll(probe_t *p, long now);

void probe_abort(probe_t *p);

#endif /* SHADOWFOX_PROBE_H */
