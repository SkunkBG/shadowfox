#ifndef SHADOWFOX_JSONW_H
#define SHADOWFOX_JSONW_H

#include <stddef.h>

/* Пишет JSON в буфер фиксированного размера. Своё, а не библиотека:
   зависимостей кроме libc в проекте нет, а нужен только вывод.

   Переполнение не бросает и не обрезает молча: буфер помечается как
   испорченный, дальнейшие записи игнорируются, и json_done вернёт -1.
   Так ошибка не теряется по дороге, но и проверять каждый вызов не надо. */
typedef struct {
    char  *buf;
    size_t size;
    size_t len;
    int    failed;
    int    depth;
    int    need_comma;  /* внутри текущего уровня уже что-то есть */
} json_t;

void json_init(json_t *j, char *buf, size_t size);

void json_obj_open(json_t *j);
void json_obj_close(json_t *j);
void json_arr_open(json_t *j);
void json_arr_close(json_t *j);

/* Ключ для следующего значения внутри объекта. */
void json_key(json_t *j, const char *key);

void json_str(json_t *j, const char *value);
void json_int(json_t *j, long value);
void json_bool(json_t *j, int value);
void json_raw(json_t *j, const char *raw);   /* уже готовый JSON */
void json_rawn(json_t *j, const char *raw, size_t len);   /* кусок без NUL */

/* Сокращения для пар ключ-значение. */
void json_kv_str(json_t *j, const char *key, const char *value);
void json_kv_int(json_t *j, const char *key, long value);
void json_kv_bool(json_t *j, const char *key, int value);

/* Массив строк из value, разделённых sep. Пустая строка даёт []. */
void json_kv_str_list(json_t *j, const char *key, const char *value, char sep);

/* Возвращает 0, если всё поместилось и скобки сбалансированы. */
int  json_done(const json_t *j);

#endif /* SHADOWFOX_JSONW_H */
