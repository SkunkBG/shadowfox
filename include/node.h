#ifndef SHADOWFOX_NODE_H
#define SHADOWFOX_NODE_H

/* Разобранная share-ссылка. Поля названы так же, как параметры ссылки,
   чтобы при чтении конфига было видно, откуда что взялось. */

#define NODE_TAG_MAX  128
#define NODE_ADDR_MAX 256
#define NODE_ID_MAX   128
#define NODE_STR_MAX  256

typedef struct {
    char tag[NODE_TAG_MAX];        /* имя из #фрагмента либо host:port */
    char protocol[16];             /* пока только vless */
    char address[NODE_ADDR_MAX];
    int  port;
    int  address_is_ipv6;

    char id[NODE_ID_MAX];          /* uuid — секрет, в журнал не пишется */
    char flow[64];
    char encryption[2048];         /* VLESS Encryption — строка длинная */
    int  flow_dropped;             /* flow был, но транспорт его не умеет */
    int  fp_fixed;                 /* незнакомый uTLS-отпечаток заменён на chrome */

    char network[16];              /* tcp, ws, grpc, xhttp, httpupgrade */
    char security[16];             /* none, tls, reality */
    char header_type[32];          /* type=http для tcp */

    char sni[NODE_STR_MAX];
    char alpn[NODE_STR_MAX];       /* как в ссылке, через запятую */
    char fingerprint[32];          /* uTLS */
    int  allow_insecure;

    char public_key[NODE_ID_MAX];  /* reality pbk */
    char short_id[64];             /* reality sid */
    char spider_x[NODE_STR_MAX];   /* reality spx */

    char path[NODE_STR_MAX];       /* ws, xhttp, httpupgrade */
    char host[NODE_STR_MAX];       /* заголовок Host */
    char mode[32];                 /* xhttp: auto, packet-up, stream-up, stream-one; grpc: multi */
    char service_name[NODE_STR_MAX]; /* grpc */
    char authority[NODE_STR_MAX];    /* grpc */
} node_t;

/* Разбирает vless://... Возвращает 0 при успехе.
   При ошибке кладёт причину в err (если он не NULL). */
int node_from_link(const char *link, node_t *n, char *err, unsigned err_size);

#endif /* SHADOWFOX_NODE_H */
