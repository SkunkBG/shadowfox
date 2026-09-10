#ifndef SHADOWFOX_SUBS_H
#define SHADOWFOX_SUBS_H

#include <stddef.h>

/* Подписка: строка https://… в файле ссылок вместо самих ссылок.
   Так их раздают панели (Remnawave и прочие): один адрес, по нему
   сервер отдаёт список серверов, обычно в base64. Адрес — секрет,
   он и есть доступ; в журнал попадает только имя узла.

   Скачивает wget-ssl из Entware (или curl), как и обновление. Своего
   TLS в демоне нет и не будет: ради одной загрузки в сутки тащить
   криптографию в бинарник незачем. */

#define SUBS_HOST_MAX 128
#define SUBS_CACHE     "subscription.cache"   /* в conf_dir, 0600 */

/* Строка — адрес подписки? */
int subs_is_url(const char *line);

/* Сколько адресов подписок в тексте файла ссылок. */
int subs_count_urls(const char *text);

/* Имя узла первой подписки в тексте, пусто — если её нет. */
void subs_first_host(const char *text, char *dst, size_t size);

/* Имя узла из адреса, для журнала и страницы. */
void subs_host(const char *url, char *dst, size_t size);

/* Раскрывает подписки в тексте файла ссылок: обычные строки копирует,
   каждый адрес заменяет содержимым, что вернул сервер (base64
   раскрывается). Всё скачанное сохраняется в кеш; если сервер не
   ответил, берётся кеш, чтобы ядро поднималось и без сети.
   Возвращает число адресов в тексте; *from_cache = 1, если пришлось
   взять кеш; err — почему. Без адресов текст копируется как есть. */
int subs_expand(const char *text, const char *cache_path, const char *hwid,
                char *out, size_t size, int *from_cache,
                char *err, size_t err_size);

/* Одна загрузка. Для проверок принимает file://. Возвращает длину тела
   либо -1 и причину в err. Тело уже раскрыто из base64, если было. */
long subs_fetch(const char *url, const char *hwid, char *out, size_t size,
                char *err, size_t err_size);

/* Файл с постоянным идентификатором устройства для панели, в conf_dir.
   Панели с лимитом устройств (Remnawave) без заголовка x-hwid отдают
   заглушку «App not supported» вместо списка. Идентификатор случайный,
   создаётся один раз и хранится 0600: для панели роутер — одно из
   устройств пользователя. */
#define SUBS_HWID_FILE "hwid"

#endif
