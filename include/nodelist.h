#ifndef SHADOWFOX_NODELIST_H
#define SHADOWFOX_NODELIST_H

#include "node.h"

/* Столько узлов хватает с запасом, а фиксированный массив избавляет
   от динамической памяти в долгоживущем демоне на роутере. */
#define NODELIST_MAX 32

/* Серверов немного по замыслу: каждому нужен свой вход SOCKS, своё
   подключение в роутере и своя политика доступа — всё это заводится
   руками, и десятками такое не держат. */
#define NODELIST_SERVERS_MAX 4

typedef struct {
    char name[48];
    int  socks_port;   /* 0 — назначить от базового */
    int  nodes;        /* сколько ссылок попало сюда */
} nl_server_t;

typedef struct {
    node_t items[NODELIST_MAX];

    /* К какому серверу относится узел. Отдельным массивом, чтобы не
       трогать node_t: он описывает ссылку, а не нашу раскладку. */
    unsigned char owner[NODELIST_MAX];
    int    count;

    nl_server_t servers[NODELIST_SERVERS_MAX];
    int    server_count;

    int    skipped;   /* строк, которые не удалось разобрать */
} nodelist_t;

/* Начинает новый сервер. socks_port 0 означает «назначить от базового».
   Возвращает его номер либо -1, если серверов уже слишком много. */
int  nodelist_begin_server(nodelist_t *l, const char *name, int socks_port);

/* Порт входа сервера: заданный явно либо base + номер. */
int  nodelist_port(const nodelist_t *l, int server, int base);

void nodelist_init(nodelist_t *l);

/* Добавляет одну ссылку. Возвращает 0 при успехе. */
int  nodelist_add_link(nodelist_t *l, const char *link,
                       char *err, unsigned err_size);

/* Разбирает тело подписки: либо base64 от списка ссылок, либо сам
   список ссылок построчно. Понимает и разбивку на серверы:

       [Болгария]
       socks = 1301
       vless://...

   Ссылки до первого заголовка попадают в сервер по умолчанию — файл
   из одних ссылок продолжает работать как раньше. Нераспознанные строки пропускаются и
   считаются в l->skipped — одна битая ссылка не должна ронять всю
   подписку. Возвращает число добавленных узлов, либо -1. */
int  nodelist_from_subscription(nodelist_t *l, const char *body);

#endif /* SHADOWFOX_NODELIST_H */
