#ifndef SHADOWFOX_DIGEST_H
#define SHADOWFOX_DIGEST_H

#include <stddef.h>

/* MD5 и SHA-256 нужны ровно для одного: проверить логин и пароль от
   роутера его же схемой. Своя реализация вместо библиотеки — тащить
   OpenSSL на роутер ради двух хешей несоразмерно. */

void md5(const void *data, size_t len, unsigned char out[16]);
void sha256(const void *data, size_t len, unsigned char out[32]);

/* Шестнадцатеричная запись в нижнем регистре, с завершающим нулём.
   dst должен вмещать len*2 + 1 байт. */
void hex_encode(const unsigned char *src, size_t len, char *dst);

#endif /* SHADOWFOX_DIGEST_H */
