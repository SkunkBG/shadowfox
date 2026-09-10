#ifndef SHADOWFOX_XJSON_H
#define SHADOWFOX_XJSON_H

#include "node.h"
#include "nodelist.h"

#include <stddef.h>

/* Подписка в формате Xray JSON: панель отдаёт массив готовых конфигов
   ядра, по одному на «сервер». В таком конфиге может быть сборка из
   нескольких серверов с балансировщиком и наблюдателем — то, чего из
   ссылки vless:// не собрать. Мы не разбираем его целиком: ядру нужен
   он сам. Вырезаем только куски верхнего уровня как есть, а входы,
   журнал и DNS подставляем свои. Разбор — сканер по скобкам и строкам,
   без построения дерева. */

#define XJSON_MAX NODELIST_MAX

typedef struct {
    const char *ptr;
    size_t      len;
} xjson_span_t;

typedef struct {
    char         remarks[NODE_TAG_MAX];   /* имя, как в списке серверов */
    xjson_span_t whole;                   /* весь объект конфига */
} xjson_item_t;

typedef struct {
    xjson_item_t items[XJSON_MAX];
    int          count;
    int          skipped;    /* объектов без outbounds */
} xjson_t;

/* Текст похож на Xray JSON (массив или объект), а не на список ссылок? */
int xjson_looks_like(const char *text);

/* Разбирает массив конфигов либо один конфиг. Куски ссылаются на text —
   он должен жить, пока живёт результат. Возвращает число конфигов. */
int xjson_parse(const char *text, xjson_t *x);

/* Порты серверов из outbounds конфига — для пассивной проверки туннеля. */
int xjson_ports(const xjson_item_t *it, int *ports, int max);

/* Служебное, для сборки конфига и проверок: обход членов объекта.
   Возвращает 1 и заполняет key/val, сдвигая *p; 0 — членов больше нет;
   -1 — не JSON. */
int xjson_next_member(const char **p, const char *end,
                      xjson_span_t *key, xjson_span_t *val);

/* Конец значения JSON, начинающегося в p (строка, число, объект,
   массив, литерал), либо NULL, если оно битое. */
const char *xjson_skip_value(const char *p, const char *end);

/* Пробелы. */
const char *xjson_ws(const char *p, const char *end);

#endif
