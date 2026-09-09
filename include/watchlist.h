#ifndef SHADOWFOX_WATCHLIST_H
#define SHADOWFOX_WATCHLIST_H

/* Списки доменов и подсетей, которые нужно заворачивать в туннель.

   Память вся статическая: демон живёт на роутере месяцами, и растущая
   куча там ни к чему. Ограничения ниже подобраны с запасом под реальные
   списки в несколько тысяч доменов. */

#define WL_GROUPS_MAX   16
#define WL_NAME_MAX     32
#define WL_IFACE_MAX    32
#define WL_SETNAME_MAX  32          /* ipset не принимает имена длиннее 31 */
#define WL_DOMAINS_MAX  4096
/* 4096: у WhatsApp и Telegram по нескольку сотен зашитых адресов на
   каждую семью, и на 1024 живые списки не помещались — хвост молча
   отбрасывался. По 20 байт на запись это 80 КБ. */
#define WL_CIDRS_MAX    4096
#define WL_POOL_BYTES   (192 * 1024)

/* Метки и таблицы маршрутизации.

   hrneo по умолчанию берёт метки от 12289 (0x3001) и таблицы от 301 —
   то есть живёт в младших битах метки. Поэтому мы занимаем старшие 16
   бит целиком и ставим метку через маску: младшая половина, где сидит
   hrneo и всё остальное, остаётся нетронутой. Затирать чужую метку,
   когда правила совпали на одном пакете, недопустимо. */
#define WL_MARK_HIGH    0x5346u     /* "SF" в старшей половине */
#define WL_MARK_MASK    0xFFFF0000u
#define WL_MARK_OF(i)   (((WL_MARK_HIGH + (unsigned)(i)) << 16))
#define WL_TABLE_BASE   5346

typedef enum {
    WL_NAMESPACE = 0,   /* example.com — сам домен и все поддомены */
    WL_WILDCARD,        /* *.example.com — только поддомены */
    WL_EXACT            /* =example.com — точное совпадение */
} wl_kind_t;

typedef struct {
    unsigned      offset;   /* смещение имени в пуле */
    unsigned char len;      /* длина имени: strlen на каждый поиск был дорог */
    unsigned char kind;
    unsigned char group;
} wl_domain_t;

typedef struct {
    unsigned char addr[16];
    unsigned char family;   /* 4 или 6 */
    unsigned char prefix;
    unsigned char group;
} wl_cidr_t;

/* Цель группы бывает двух видов, и заворачивается трафик в них
   по-разному. Различаем по наличию /sys/class/net/<имя>. */
typedef enum {
    WL_TARGET_UNKNOWN = 0,
    WL_TARGET_IFACE,     /* настоящее устройство: своя метка и таблица */
    WL_TARGET_POLICY     /* политика Keenetic: её метка, маршрутизирует роутер */
} wl_target_t;

typedef struct {
    char     name[WL_NAME_MAX];
    char     iface[WL_IFACE_MAX];
    unsigned char enabled;       /* выключенная группа не метит и не ловит */
    unsigned char target;        /* wl_target_t */
    unsigned policy_mark;        /* метка политики, полученная из RCI */
    char     ipset4[WL_SETNAME_MAX];
    char     ipset6[WL_SETNAME_MAX];
    unsigned mark;
    unsigned table;
} wl_group_t;

typedef struct {
    wl_group_t  groups[WL_GROUPS_MAX];
    int         group_count;

    wl_domain_t domains[WL_DOMAINS_MAX];
    int         domain_count;

    wl_cidr_t   cidrs[WL_CIDRS_MAX];
    int         cidr_count;

    char        pool[WL_POOL_BYTES];
    unsigned    pool_used;

    int         skipped;    /* строк, которые не удалось разобрать */
} wl_t;

void wl_init(wl_t *w);

/* Читают файлы вида:

       [имя-группы]
       interface = Proxy0
       enabled = no
       example.com

   Битая строка пропускается и считается в w->skipped: одна опечатка не
   должна обнулять список из тысячи записей. Возвращают 0, либо -1 при
   ошибке чтения. Отсутствие файла ошибкой не считается. */
int wl_load_domains(wl_t *w, const char *path);
int wl_load_cidrs(wl_t *w, const char *path);

/* Возвращают номер группы либо -1. Выигрывает самое длинное совпадение:
   так порядок строк в файле не влияет на результат, а более точное
   правило всегда перекрывает общее. */
int wl_match_domain(const wl_t *w, const char *host);
int wl_match_ip(const wl_t *w, int family, const unsigned char *addr);

/* Определяет вид цели каждой группы: смотрит, есть ли такое устройство
   в /sys/class/net. sysnet_dir нужен тестам, обычно NULL.
   Возвращает число групп, оказавшихся политиками Keenetic. */
int wl_classify_targets(wl_t *w, const char *sysnet_dir);

/* Наборы общие на цель: все группы, ведущие в одну политику или на одно
   устройство, кладут адреса в один набор, как у HydraRoute (набор
   зовётся именем политики). Эта функция даёт номер группы-владельца
   набора — первой с тем же набором, — чтобы память адресов и подсчёты
   не считали один набор дважды. */
int wl_set_owner(const wl_t *w, int group);

const char *wl_domain_text(const wl_t *w, int index);

/* Печатает подсеть в привычном виде "192.0.2.0/24".
   Возвращает dst либо NULL, если не поместилось. */
const char *inet_ntop_prefix(const wl_cidr_t *c, char *dst, unsigned size);

#endif /* SHADOWFOX_WATCHLIST_H */
