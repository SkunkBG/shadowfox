#ifndef SHADOWFOX_SNICAP_H
#define SHADOWFOX_SNICAP_H

#include <stddef.h>

/* Перехват имени сервера из TLS ClientHello.

   Зачем он нужен помимо перехвата DNS. Схема «только DNS» узнаёт адрес
   из ответа резолвера, а значит слепа там, где ответа нет:

     - у устройства тёплый кеш и оно ничего не спрашивает;
     - у клиента свой DoH/DoT/DoQ и ответ до нас не долетает;
     - адрес зашит в приложении и DNS не участвует вовсе.

   В ClientHello имя сервера идёт открытым текстом до всякого шифрования,
   поэтому здесь мы узнаём не предполагаемый адрес, а тот самый, к
   которому клиент прямо сейчас пошёл. Цена — мы узнаём об этом на одно
   соединение позже: оно уже установлено мимо туннеля, и его приходится
   обрывать, чтобы приложение переустановило соединение уже по политике.

   Чего не закрывает и это: ECH прячет имя внутри шифрования, а
   iCloud Private Relay по устройству и есть отдельный туннель. */

#define SCAP_IFACE_MAX 32
#define SCAP_BUF_BYTES 2048

/* Незавершённые приветствия. С постквантовым обменом ключей ClientHello
   вырос до ~1,7 КБ и перестал помещаться в один сегмент, а Chrome ещё и
   перемешивает расширения — имя сервера может оказаться во втором. Хвост
   первого сегмента держим по 5-tuple до прихода продолжения. Восьми
   слотов хватает: таких приветствий единицы в секунду, живут они
   миллисекунды. */
#define SCAP_PARTIAL_MAX   8
#define SCAP_PARTIAL_BYTES 4096
#define SCAP_PARTIAL_TTL   2      /* секунд */

/* 253 — предел длины имени в DNS, плюс завершающий ноль. */
#define SCAP_NAME_MAX  256

typedef struct {
    unsigned char family;         /* 4 или 6 */
    unsigned char src[16];
    unsigned char dst[16];
    unsigned      sport;
    unsigned      dport;
    char          name[SCAP_NAME_MAX];
} sni_hit_t;

typedef struct {
    int           fd;
    char          iface[SCAP_IFACE_MAX];
    int           filtered;        /* фильтр ядра принят */

    unsigned long seen;            /* пакетов прочитано */
    unsigned long parsed;          /* имён разобрано */

    /* Причины отказа врозь: «не TLS» — это норма работы фильтра, а
       «не разобрался» — уже повод смотреть. Общий счётчик их смешал бы,
       и на диагнозе это уже подводило. */
    unsigned long drop_nottls;     /* не TCP/443 или не ClientHello */
    unsigned long drop_bad;        /* похоже на ClientHello, но не сошлось */
    unsigned long drop_foreign;    /* не адресован роутеру: чужой или мост */

    /* Склейка. «Начато» без «склеено» — продолжение так и не пришло или
       не сошлось по номеру последовательности. */
    unsigned long partial_kept;    /* приветствий, ушедших ждать продолжения */
    unsigned long reassembled;     /* из них собрано и разобрано */
    unsigned long partial_lost;    /* сгорело по сроку или не сошлось */

    struct {
        unsigned char  family;
        unsigned char  src[16], dst[16];
        unsigned       sport, dport;
        unsigned       next_seq;   /* какой seq ждём следующим */
        size_t         len;
        long           at;
        unsigned char  data[SCAP_PARTIAL_BYTES];
    } partial[SCAP_PARTIAL_MAX];

    unsigned char buf[SCAP_BUF_BYTES];
} scap_t;

/* Одна команда фильтра ядра. Раскладка совпадает со struct sock_filter
   из linux/filter.h — так массив живёт в переносимой части файла и его
   можно прогнать тестом на любой машине, а не только там, где есть
   заголовки ядра. Совпадение размеров проверяется при сборке. */
typedef struct {
    unsigned short code;
    unsigned char  jt;
    unsigned char  jf;
    unsigned int   k;
} scap_insn_t;

/* Байткод фильтра и его длина. Нужен тесту: ошибка здесь не ломает
   сборку и не пишет в журнал — перехват просто молча не срабатывает. */
const scap_insn_t *scap_filter(unsigned *count);

void scap_init(scap_t *c);

/* Открывает сокет захвата на интерфейсе. Возвращает 0 при успехе.
   Только Linux; в остальных системах вернёт -1 с внятной причиной. */
int  scap_open(scap_t *c, const char *iface, char *err, unsigned err_size);
void scap_close(scap_t *c);

/* Разбирает IP-пакет: IPv4 или IPv6, TCP на порт назначения 443, запись
   TLS handshake, ClientHello и в нём расширение server_name.

   Возвращает 0 при успехе, -1 если это не наш пакет, -2 если пакет
   похож на ClientHello, но разбор не сошёлся, -3 если приветствие
   обрывается на границе сегмента — продолжение в следующем.

   Вынесено отдельно от сокета намеренно: разбор проверяется тестами на
   любой машине, а сокет живёт только на Linux. Данные тут приходят из
   сети и полностью подконтрольны клиенту, поэтому каждый шаг проверяет
   границы, а имя — состав символов. */
int  scap_extract(const unsigned char *pkt, size_t len, sni_hit_t *out);

/* Один пакет: разбор, склейка с ожидающим продолжением, вызов cb.
   pkttype — направление из sockaddr_ll, -1 если неизвестно; now — время
   для срока жизни склеек. Отдельно от сокета, чтобы проверяться тестами.
   Возвращает 1, если имя разобрано. */
int  scap_handle(scap_t *c, const unsigned char *pkt, size_t len, int pkttype,
                 long now, void (*cb)(const sni_hit_t *, void *), void *ctx);

/* Читает готовые пакеты и вызывает cb на каждое разобранное имя.
   Возвращает число разобранных. */
int  scap_poll(scap_t *c, void (*cb)(const sni_hit_t *, void *), void *ctx);

#endif /* SHADOWFOX_SNICAP_H */
