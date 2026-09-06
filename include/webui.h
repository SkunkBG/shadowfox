#ifndef SHADOWFOX_WEBUI_H
#define SHADOWFOX_WEBUI_H

#include "config.h"
#include "http.h"

struct engine;

/* Веб-интерфейс: одна страница и несколько путей к данным.

   Страница вшита в бинарник уже сжатой — на роутере нет ни места под
   внешние файлы, ни смысла жать её при каждом запросе. */

/* Поднимает сервер. Адрес берётся из настроек, а если он пуст — с
   интерфейса локальной сети. Возвращает 0 при успехе. */
int  webui_addr(const config_t *cfg, char *out, unsigned size,
                char *err, unsigned err_size);
int  webui_needs_rebind(const http_t *h, const config_t *cfg);

int  webui_open(http_t *h, const config_t *cfg, char *err, unsigned err_size);

/* Обрабатывает готовые соединения. Вызывать из главного цикла. */
void webui_poll(http_t *h, struct engine *e, const config_t *cfg);

#endif /* SHADOWFOX_WEBUI_H */
