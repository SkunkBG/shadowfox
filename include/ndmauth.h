#ifndef SHADOWFOX_NDMAUTH_H
#define SHADOWFOX_NDMAUTH_H

/* Проверка логина и пароля от роутера — его же схемой.

   Keenetic отвечает на GET /auth кодом 401 и заголовками X-NDM-Realm и
   X-NDM-Challenge. Ответ считается так:

       md5  = MD5(логин ":" realm ":" пароль)
       ответ = SHA256(challenge + шестнадцатеричный md5)

   и отправляется в POST /auth заголовками X-NDM-Login и X-NDM-Password.
   Пароль в открытом виде по сети не уходит и у нас нигде не хранится. */

typedef enum {
    NDM_OK = 0,       /* логин с паролем подошли */
    NDM_DENIED,       /* не подошли */
    NDM_UNAVAILABLE   /* роутер не ответил или ответил непонятно */
} ndm_result_t;

ndm_result_t ndm_check_password(const char *host, int port,
                                const char *login, const char *password,
                                char *err, unsigned err_size);

/* Разбор заголовков из ответа: вынесено ради проверок. */
int ndm_header(const char *response, const char *name,
               char *out, unsigned out_size);

/* Считает ответ на запрос. Нужен тестам и вызывается изнутри. */
void ndm_answer(const char *realm, const char *challenge,
                const char *login, const char *password, char out[65]);

#endif /* SHADOWFOX_NDMAUTH_H */
