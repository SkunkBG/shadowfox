#ifndef SHADOWFOX_TCPSTAT_H
#define SHADOWFOX_TCPSTAT_H

#include <stddef.h>
#include <sys/types.h>

/* Пассивная проверка туннеля.

   Активная проверка — запрос через сервер по расписанию — оказалась
   сердцебиением, по которому провайдер распознаёт туннель: одинаковый
   размер, ровный период. Поэтому ни байта не отправляем, а читаем то,
   что ядро уже знает: состояние его собственных TCP-соединений с
   сервером из /proc/net/tcp.

     ESTABLISHED  — соединение с сервером есть;
     SYN_SENT     — ядро стучится, сервер не отвечает: адрес закрыт;
     retrnsmt     — повторы на живом соединении: данные не доходят.

   Сокеты ядра узнаём по inode через /proc/<pid>/fd, чтобы не путать с
   чужими соединениями на тот же порт. */

#define TCPSTAT_INODES_MAX 1024
#define TCPSTAT_PORTS_MAX  32

#define TCPSTAT_REMOTES_MAX 16

typedef struct {
    int           established;   /* соединений с сервером */
    int           syn_sent;      /* ждут ответа на SYN */
    unsigned long retrans;       /* повторов на установленных, сумма */
    /* Адреса серверов, к которым у ядра есть сокеты: по ним наблюдение
       за SYN/SYN-ACK отличает соединения ядра от чужих на тот же порт. */
    unsigned char remotes[TCPSTAT_REMOTES_MAX][16];
    unsigned char remote_fam[TCPSTAT_REMOTES_MAX];   /* 4 или 6 */
    int           remote_count;
} tcpstat_t;

/* Разбирает текст /proc/net/tcp или tcp6. Учитывает только сокеты с
   inode из списка (отсортирован не обязательно) и удалённым портом из
   ports. Возвращает число учтённых строк. Отдельно от чтения файлов —
   ради тестов на любой машине. */
int tcpstat_parse(const char *text, const unsigned long *inodes, int n_inodes,
                  const int *ports, int n_ports, tcpstat_t *out);

/* inode сокетов процесса из /proc/<pid>/fd. Возвращает число, -1 если
   процесса нет. Только Linux. */
int tcpstat_inodes(pid_t pid, unsigned long *inodes, int max);

/* Полный сбор: inode ядра, tcp и tcp6. Возвращает 0 при успехе. */
int tcpstat_collect(pid_t pid, const int *ports, int n_ports, tcpstat_t *out);

#endif /* SHADOWFOX_TCPSTAT_H */
