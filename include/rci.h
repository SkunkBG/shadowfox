#ifndef SHADOWFOX_RCI_H
#define SHADOWFOX_RCI_H

#include <stddef.h>

/* Клиент RCI — локального интерфейса управления Keenetic.

   Через него берётся метка политики доступа: штатный прокси-клиент
   Keenetic не является сетевым устройством, и завернуть в него трафик
   через `ip route dev` нельзя. Роутер маршрутизирует по собственной
   метке политики, поэтому метку надо спросить у него.

   Своя реализация HTTP вместо библиотеки: запрос простой, ответ
   короткий, а тащить зависимость на роутер ради одного GET незачем. */

#define RCI_HOST_MAX  64
#define RCI_BODY_MAX  16384   /* show version с components не влезал в 8 КБ */

typedef struct {
    char host[RCI_HOST_MAX];
    int  port;
    int  timeout;          /* секунд на весь обмен */
    char token[128];       /* для прошивок, требующих авторизации */
} rci_t;

void rci_init(rci_t *r);

/* Выполняет запрос. method — "GET" или "POST"; body может быть NULL.
   Ответ без заголовков кладётся в out. Возвращает код HTTP либо -1. */
int  rci_request(const rci_t *r, const char *method, const char *path,
                 const char *body, char *out, unsigned out_size);

/* Читает метку политики. Возвращает 0 и кладёт значение в *mark.
   Метка приходит в кавычках и без префикса 0x — снимаем и то, и другое. */
int  rci_policy_mark(const rci_t *r, const char *policy, unsigned *mark);

/* Модель и прошивка из show version: «Keenetic Viva (KN-1910)», «4.3.6».
   Пустые строки, если роутер не ответил. 0 — успех. */
/* Строковое поле из ответа RCI, с отступами и без. 1 — нашлось. */
int  rci_field(const char *text, const char *name, char *out, size_t out_size);

int  rci_device_info(const rci_t *r, char *model, size_t model_size,
                     char *osver, size_t osver_size);

/* Создаёт политику, если её ещё нет, и сохраняет конфигурацию роутера.
   Существующую не трогает. */
int  rci_policy_create(const rci_t *r, const char *policy);

/* Снимает кавычки и префикс 0x, разбирает шестнадцатеричное значение. */
int  rci_parse_mark(const char *text, unsigned *mark);

#endif /* SHADOWFOX_RCI_H */
