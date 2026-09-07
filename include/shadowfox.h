/* shaper — менеджер Xray и доменной маршрутизации для роутеров Keenetic */
#ifndef SHADOWFOX_H
#define SHADOWFOX_H

#ifndef VERSION
#define VERSION "0.0.0-dev"
#endif

#define SHADOWFOX_NAME     "shaper"
#define SHADOWFOX_DAEMON   "shadowfoxd"

/* Пути по умолчанию. Переопределяются в shadowfox.conf и флагами CLI. */
#define DEFAULT_CONF_DIR    "/opt/etc/shadowfox"
#define DEFAULT_CONF_FILE   DEFAULT_CONF_DIR "/shadowfox.conf"
#define DEFAULT_PID_FILE    "/opt/var/run/shadowfoxd.pid"
#define DEFAULT_LOG_FILE    "/opt/var/log/shadowfoxd.log"

/* Ошибки ядра. На tmpfs, а не на флешке: ядро пишет их само, по строке
   на каждое неудачное соединение, и на USB-накопителе это была бы
   ежедневная порция записи ни за что. После перезагрузки файл пуст —
   это ожидаемо, нам нужны последние ошибки, а не история. */
#define XRAY_ERROR_LOG      "/tmp/shadowfox-xray.log"
#define XRAY_ERROR_LOG_CAP  (256 * 1024)   /* сверх этого — обрезаем */

#endif /* SHADOWFOX_H */
