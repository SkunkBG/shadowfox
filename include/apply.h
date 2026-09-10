#ifndef SHADOWFOX_APPLY_H
#define SHADOWFOX_APPLY_H

#define APPLY_PATH_MAX 256

typedef struct {
    char xray_bin[APPLY_PATH_MAX];      /* чем проверять и что запускать */
    char config_path[APPLY_PATH_MAX];   /* куда класть готовый конфиг */
    int  test_timeout;                  /* секунд на проверку конфига */
    int  uid, gid;                      /* владелец готового конфига; 0 — root */
} apply_opts_t;

void apply_defaults(apply_opts_t *o);

/* Ищет xray среди известных путей. Возвращает 1, если нашёлся. */
int  apply_find_xray(char *dst, unsigned dst_size);

/* Кладёт json в config_path, но только если xray его принял.

   Порядок важен: пишем во временный файл рядом, проверяем его через
   `xray run -test`, и лишь потом атомарно переименовываем. Если
   проверка не прошла, прежний конфиг остаётся нетронутым.

   Возвращает 0 при успехе. Вывод xray кладётся в err. */
int  apply_config(const apply_opts_t *o, const char *json,
                  char *err, unsigned err_size);

#endif /* SHADOWFOX_APPLY_H */
