#!/bin/sh
# Подключает фид Shadow Fox к opkg на роутере Keenetic.
#
#   curl -Ls https://skunkbg.github.io/shadowfox/add-repo.sh | sh
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

mkdir -p /opt/etc/opkg
printf 'src/gz shadowfox %s/%s\n' "$FEED_BASE" "$DIR" > "$CONF"

echo "фид подключён: $FEED_BASE/$DIR"
echo "дальше:  opkg update && opkg install shadowfox"
