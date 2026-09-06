#ifndef SHADOWFOX_NODELIST_H
#define SHADOWFOX_NODELIST_H

#include "node.h"

/* Столько узлов хватает с запасом, а фиксированный массив избавляет
   от динамической памяти в долгоживущем демоне на роутере. */
#define NODELIST_MAX 32

typedef struct {
    node_t items[NODELIST_MAX];
    int    count;
    int    skipped;   /* строк, которые не удалось разобрать */
} nodelist_t;

void nodelist_init(nodelist_t *l);

/* Добавляет одну ссылку. Возвращает 0 при успехе. */
int  nodelist_add_link(nodelist_t *l, const char *link,
                       char *err, unsigned err_size);

/* Разбирает тело подписки: либо base64 от списка ссылок, либо сам
   список ссылок построчно. Нераспознанные строки пропускаются и
   считаются в l->skipped — одна битая ссылка не должна ронять всю
   подписку. Возвращает число добавленных узлов, либо -1. */
int  nodelist_from_subscription(nodelist_t *l, const char *body);

#endif /* SHADOWFOX_NODELIST_H */
