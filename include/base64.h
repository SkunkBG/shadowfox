#ifndef SHADOWFOX_BASE64_H
#define SHADOWFOX_BASE64_H

#include <stddef.h>

/* Декодирует base64. Терпим к тому, что реально приходит в подписках:
   URL-safe алфавит (-_ вместо +/), отсутствующее выравнивание '=',
   переводы строк и пробелы внутри.

   Возвращает длину результата, либо -1 при недопустимом символе или
   нехватке буфера. Результат всегда завершён нулём. */
long base64_decode(const char *in, char *out, size_t out_size);

#endif /* SHADOWFOX_BASE64_H */
