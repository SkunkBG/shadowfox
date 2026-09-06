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

#endif /* SHADOWFOX_H */
