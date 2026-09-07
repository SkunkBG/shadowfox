#!/bin/sh
# Подключает фид Shadow Fox к opkg на роутере Keenetic.
#
#   curl -fsSL https://skunkbg.github.io/shadowfox/add-repo.sh | sh
set -eu

FEED_BASE=${FEED_BASE:-https://skunkbg.github.io/shadowfox/keenetic}
CONF=/opt/etc/opkg/shadowfox.conf

[ -f /opt/etc/entware_release ] || {
    echo "не найден /opt/etc/entware_release — это не Entware" >&2
    exit 1
}


ARCH=$(grep '^arch=' /opt/etc/entware_release | cut -d= -f2)

# Имена каталогов фида у Entware исторически не совпадают с названиями
# архитектур: mipselsf-k3.4, но арка при этом mipsel-3.4.
case "$ARCH" in
    aarch64) DIR=aarch64-k3.10 ;;
    mipsel)  DIR=mipselsf-k3.4 ;;
    mips)    DIR=mipssf-k3.4   ;;
    *) echo "неизвестная архитектура: $ARCH" >&2; exit 1 ;;
esac

# Проверяем, что фид опубликован, до того как записать конфиг: иначе
# opkg update потом ругается непонятно на что, а причина совсем в другом.
# На свежем Entware curl может отсутствовать — тогда просто пропускаем
# проверку: она полезная, но не обязательная.
if command -v curl >/dev/null 2>&1; then
    if ! curl -fsS -o /dev/null -m 20 "$FEED_BASE/$DIR/Packages"; then
        echo "" >&2
        echo "фид $FEED_BASE/$DIR недоступен." >&2
        echo "Обычно это значит, что сборка в GitHub Actions ещё не прошла" >&2
        echo "или в настройках репозитория не включены Pages." >&2
        exit 1
    fi
fi

# opkg качает через wget, а встроенный в BusyBox не умеет TLS: фид по
# https он не возьмёт и оборвётся на «not an http or ftp url». Ставим
# нормальный wget заранее, иначе следующий шаг падает непонятно почему.
if ! /opt/bin/wget --version 2>/dev/null | grep -qi 'GNU Wget'; then
    echo "ставлю wget-ssl: без него opkg не умеет https" >&2
    opkg update  >/dev/null 2>&1 || true
    opkg install wget-ssl >/dev/null 2>&1 || \
        echo "не поставить wget-ssl — сделай это вручную" >&2
fi

mkdir -p /opt/etc/opkg
printf 'src/gz shadowfox %s/%s\n' "$FEED_BASE" "$DIR" > "$CONF"

echo "фид подключён: $FEED_BASE/$DIR"
echo "дальше:  opkg update && opkg install shadowfox"
