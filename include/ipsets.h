#ifndef SHADOWFOX_IPSETS_H
#define SHADOWFOX_IPSETS_H

#include "watchlist.h"

/* Работа с наборами ipset.

   Команды не выполняются по одной: они копятся в буфере и уходят одной
   пачкой через `ipset restore`. Иначе на каждый разрезолвленный адрес
   пришлось бы порождать процесс, а их в час пик десятки в секунду. */

#define IPS_BATCH_BYTES 16384
#define IPS_BIN_MAX     128

typedef struct {
    char     bin[IPS_BIN_MAX];              /* путь к ipset */
    char     batch[IPS_BATCH_BYTES];
    unsigned used;
    int      timeout;                       /* секунд на запуск ipset */
    unsigned queued;                        /* команд в текущей пачке */
    unsigned applied;                       /* применено всего */
    unsigned overflows;                     /* сколько раз буфер переполнялся */
} ips_t;

void ips_init(ips_t *s, const char *bin);

/* Ищет ipset среди известных путей. Возвращает 1, если нашёлся. */
int  ips_find_bin(char *dst, unsigned dst_size);

/* Ставит в очередь создание наборов всех групп.

   timeout — сколько секунд живёт запись. Без него набор копит адреса
   вечно, и через неделю в нём тысячи записей, часть из которых давно
   переехала к другим сервисам: трафик к ним уходил бы в туннель без
   всякой причины. 0 отключает старение. */
void ips_queue_create(ips_t *s, const wl_t *w, int timeout);

/* Удаляет наборы групп. Выполняется сразу, по одной команде на набор,
   и неудача не считается ошибкой: набора могло не быть.

   Нужно при смене параметров: набор, созданный без времени жизни, не
   примет записи с ним, а изменить это у существующего набора нельзя.
   Вызывать можно только когда на наборы не ссылаются правила. */
void ips_destroy(ips_t *s, const wl_t *w);

/* Удаляет наши наборы, которым больше не соответствует ни одна группа.
   Возвращает, сколько удалено. Только при снятых правилах. */
int  ips_destroy_orphans(ips_t *s, const wl_t *w);

/* Отличается ли время жизни у уже существующих наборов от нужного.

   Разбор вывода `ipset list -t` вынесен отдельно, чтобы проверяться
   тестом: ошибка здесь тихо приводит либо к потере всех накопленных
   адресов, либо к набору, который не принимает записи. */
int  ips_headers_differ(const char *text, const wl_t *w, int timeout);

/* То же, спросив у ipset. Возвращает 1, если наборы надо пересоздать,
   и при любой неясности — тоже 1: пересоздать лишний раз безопаснее,
   чем оставить набор, который не примет записи. */
int  ips_timeout_differs(ips_t *s, const wl_t *w, int timeout);

/* Число записей в наборах групп из вывода `ipset list -t`: строка
   «Name: …», ниже «Number of entries: N». Для страницы: до сих пор она
   показывала для каждой группы ноль, и всё смотрели через консоль.
   -1 — набора в выводе нет. */
void ips_entry_counts(const char *text, const wl_t *w, long *c4, long *c6);

/* То же, спросив у ipset. Возвращает 0, если удалось. */
int  ips_count_entries(ips_t *s, const wl_t *w, long *c4, long *c6);

/* Ставит в очередь добавление адреса в набор группы.
   family — 4 или 6, text — адрес в обычной записи. */
void ips_queue_add(ips_t *s, const wl_t *w, int group, int family,
                   const char *text);

/* Ставит в очередь наполнение наборов подсетями из ip.list. */
void ips_queue_cidrs(ips_t *s, const wl_t *w);

/* Отдаёт накопленное `ipset restore`. Возвращает 0 при успехе.
   Пустая очередь — успех без запуска процесса. */
int  ips_flush(ips_t *s, char *err, unsigned err_size);

/* Содержимое текущей очереди — для тестов и отладки. */
const char *ips_pending(const ips_t *s);

#endif /* SHADOWFOX_IPSETS_H */
