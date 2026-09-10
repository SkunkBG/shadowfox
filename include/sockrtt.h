#ifndef SHADOWFOX_SOCKRTT_H
#define SHADOWFOX_SOCKRTT_H

#include <stddef.h>

/* Задержка до сервера без единого лишнего пакета.
   Ядро Linux для каждого TCP-соединения хранит измеренный RTT
   (tcp_info.tcpi_rtt). Ядро Xray держит соединения с сервером, и мы
   спрашиваем у ядра их статистику через sock_diag (то, чем пользуется
   ss -ti). Ничего наружу не уходит: читаются счётчики своего же
   процесса. Чужие соединения на тот же порт отсеиваются по inode. */

typedef struct {
    int           count;     /* учтённых соединений */
    unsigned long sum_us;    /* сумма RTT, микросекунды */
    unsigned long min_us;
} sockrtt_t;

/* Разбирает ответ netlink (пачку сообщений). Только соединения с
   inode из списка и удалённым портом из ports. Возвращает число
   учтённых. Отдельно от сокета — ради тестов на любой машине. */
int sockrtt_parse(const unsigned char *buf, size_t len,
                  const unsigned long *inodes, int n_inodes,
                  const int *ports, int n_ports, sockrtt_t *out);

/* Полный опрос: IPv4 и IPv6, только ESTABLISHED. 0 при успехе, -1 —
   sock_diag недоступен (ядро без него или не Linux). */
int sockrtt_collect(const unsigned long *inodes, int n_inodes,
                    const int *ports, int n_ports, sockrtt_t *out);

/* Среднее в миллисекундах, -1 если данных нет. */
int sockrtt_ms(const sockrtt_t *r);

#endif
