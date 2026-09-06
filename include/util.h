#ifndef SHADOWFOX_UTIL_H
#define SHADOWFOX_UTIL_H

#include <stddef.h>

/* Обрезает пробелы по краям на месте. Возвращает указатель внутрь s. */
char *str_trim(char *s);

/* Копирование со строгим завершением. Возвращает 0, если влезло целиком. */
int   str_copy(char *dst, size_t dst_size, const char *src);

/* Разбор "да/нет" в 1/0. Возвращает def, если значение не распознано. */
int   parse_bool(const char *s, int def);

/* Создаёт каталог и всех родителей. Возвращает 0 при успехе. */
int   mkdir_p(const char *path, unsigned mode);

/* Пишет pid в файл. Возвращает 0 при успехе. */
int   pidfile_write(const char *path);
void  pidfile_remove(const char *path);

/* Читает pid из файла. Возвращает 0, если файла нет или процесс мёртв. */
int   pidfile_read_alive(const char *path);

#endif /* SHADOWFOX_UTIL_H */
