#ifndef SHADOWFOX_HTTP_H
#define SHADOWFOX_HTTP_H

#include <stddef.h>

/* Крошечный HTTP-сервер для веб-интерфейса.

   Своя реализация, а не библиотека: нужен один порт, несколько путей и
   отдача одной страницы. Тащить на роутер зависимость ради этого незачем.

   Слушает только заданный адрес, никогда не 0.0.0.0. neofit держал
   веб-интерфейс на всех интерфейсах без всякой авторизации — повторять
   это нельзя. */

#define HTTP_METHOD_MAX 8
#define HTTP_PATH_MAX   256
#define HTTP_QUERY_MAX  512
#define HTTP_TOKEN_MAX  64
#define HTTP_BUF_BYTES  (64 * 1024)

typedef struct {
    char        method[HTTP_METHOD_MAX];
    char        path[HTTP_PATH_MAX];
    char        query[HTTP_QUERY_MAX];
    const char *body;
    size_t      body_len;
    long        declared_len;             /* Content-Length, -1 если нет */
    char        peer[64];                 /* адрес, с которого пришли */
    /* Cookie не копируем: куки не различают порт, поэтому браузер шлёт
       нам и куки веб-интерфейса роутера с того же адреса. Заголовок
       вырастает, и копия в буфер обрезала нашу метку сессии — вход
       слетал после захода на страницу роутера. Держим указатель внутрь
       буфера запроса, как и тело. */
    const char *cookie;
    size_t      cookie_len;
    char        token[HTTP_TOKEN_MAX];   /* из заголовка авторизации */
} http_req_t;

typedef struct {
    int  fd;
    int  port;
    char bind_addr[64];
    char token[HTTP_TOKEN_MAX];          /* пусто — без проверки */
    unsigned long served;
    unsigned long rejected;
} http_t;

/* Разбирает запрос. Возвращает 0 при успехе.
   Тело не копируется: body указывает внутрь buf. */
int  http_parse_request(const char *buf, size_t len, http_req_t *out);

/* Нужны и циклу приёма: он обязан понять, доехало ли тело, до разбора. */
const char *http_headers_end(const char *buf, size_t len, size_t *skip);
long        http_content_length(const char *buf, size_t hdr_len);

/* Достаёт параметр из строки запроса. Возвращает 1, если нашёлся. */
int  http_query_get(const http_req_t *r, const char *key,
                    char *out, size_t out_size);

void http_init(http_t *h);
int  http_open(http_t *h, const char *addr, int port, char *err, unsigned err_size);
void http_close(http_t *h);
int  http_fd(const http_t *h);

/* Обрабатывает одно готовое соединение. Обработчик отвечает сам. */
void http_poll(http_t *h,
               void (*handler)(const http_req_t *req, int fd, void *ctx),
               void *ctx);

/* Отправка ответа. */
void http_send(int fd, int code, const char *ctype,
               const char *body, size_t len);
/* Ответ с двумя дополнительными заголовками: нужны входу и выходу
   (Set-Cookie и Location). Отдельная функция, чтобы не заводить общий
   механизм заголовков ради двух мест. */
void http_send_with(int fd, int code, const char *ctype,
                    const char *extra1, const char *extra2,
                    const char *body, size_t len);

void http_send_text(int fd, int code, const char *ctype, const char *body);
void http_send_gzip(int fd, const char *ctype,
                    const unsigned char *body, size_t len);

#endif /* SHADOWFOX_HTTP_H */
