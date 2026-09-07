#!/bin/sh
# Собирает .ipk из build/shadowfoxd-<arch> и ipk/rootfs.
# Использование: tools/build-ipk.sh aarch64 mipsel mips
set -eu

PKG=${PKG:-shadowfox}
PROJECT=${PROJECT:-shadowfoxd}
VERSION=${VERSION:-0.0.0}
REVISION=${REVISION:-1}
MAINTAINER=${MAINTAINER:-Shadow Fox}

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BUILD="$ROOT/build"
OUT="$BUILD/ipk"

# Кросс-компиляторская арка -> арка opkg. Ровно эти строки opkg сверяет
# с выводом `opkg print-architecture`; ошибка здесь даёт
# "package is for a different architecture" при установке.
opkg_arch() {
    case "$1" in
        aarch64) echo "aarch64-3.10" ;;
        mipsel)  echo "mipsel-3.4"   ;;
        mips)    echo "mips-3.4"     ;;
        *)       echo "" ;;
    esac
}

# Суммарный размер файлов в байтах, переносимо между macOS и Linux.
dir_size() {
    find "$1" -type f -exec wc -c {} \; 2>/dev/null | awk '{s+=$1} END {print s+0}'
}

# macOS иначе кладёт в архив ._-файлы с расширенными атрибутами,
# и opkg на роутере спотыкается о мусор.
export COPYFILE_DISABLE=1
TAR_OPTS=""
if tar --no-xattrs -cf /dev/null -T /dev/null 2>/dev/null; then
    TAR_OPTS="--no-xattrs"
fi

mkdir -p "$OUT"

for arch in "$@"; do
    ARCH=$(opkg_arch "$arch")
    if [ -z "$ARCH" ]; then
        echo "неизвестная архитектура: $arch" >&2
        exit 1
    fi

    BIN="$BUILD/$PROJECT-$arch"
    if [ ! -f "$BIN" ]; then
        echo "нет бинарника $BIN — сначала 'make $arch'" >&2
        exit 1
    fi

    STAGE="$BUILD/stage-$arch"
    rm -rf "$STAGE"
    mkdir -p "$STAGE/data" "$STAGE/control"

    cp -R "$ROOT/ipk/rootfs/." "$STAGE/data/"
    find "$STAGE/data" -name '.DS_Store' -delete

    mkdir -p "$STAGE/data/opt/bin"
    cp "$BIN" "$STAGE/data/opt/bin/$PROJECT"
    chmod 0755 "$STAGE/data/opt/bin/$PROJECT"
    chmod 0755 "$STAGE/data/opt/sbin/shadowfox-update"

    SIZE=$(dir_size "$STAGE/data")

    sed -e "s|@PKG@|$PKG|g" \
        -e "s|@VERSION@|$VERSION-$REVISION|g" \
        -e "s|@ARCH@|$ARCH|g" \
        -e "s|@INSTALLED_SIZE@|$SIZE|g" \
        -e "s|@MAINTAINER@|$MAINTAINER|g" \
        "$ROOT/ipk/control/control.in" > "$STAGE/control/control"

    for f in conffiles postinst prerm; do
        [ -f "$ROOT/ipk/control/$f" ] || continue
        cp "$ROOT/ipk/control/$f" "$STAGE/control/$f"
    done

    # Путь к pid-файлу указан в трёх местах: настройки демона, init-скрипт
    # и оба ndm-хука. Разойдись они — демон пишет по одному пути, хук ищет
    # по другому и молча ничего не делает. Ровно так и случилось при
    # переименовании проекта: файл настроек не попал под замену, и хуки
    # бездействовали, ничем себя не выдавая.
    conf_pid=$(sed -n 's/^pidFile=//p' "$STAGE/data/opt/etc/shadowfox/shadowfox.conf")
    init_pid=$(sed -n 's/^PIDFILE=//p' "$STAGE/data/opt/etc/init.d/S99shadowfox")

    for hook in "$STAGE"/data/opt/etc/ndm/*/015-shadowfox.sh; do
        hook_pid=$(sed -n 's/^pidfile="\(.*\)"$/\1/p' "$hook")
        if [ "$hook_pid" != "$conf_pid" ]; then
            echo "хук $(basename "$hook") ищет pid в '$hook_pid'," >&2
            echo "а демон пишет его в '$conf_pid'" >&2
            exit 1
        fi
    done

    if [ "$init_pid" != "$conf_pid" ]; then
        echo "init-скрипт указывает pid '$init_pid', а настройки '$conf_pid'" >&2
        exit 1
    fi

    # Каждый conffile обязан реально лежать в пакете. Рассинхрон между
    # списком и файлами opkg не заметит, а пользователь потеряет свои
    # настройки при первом же обновлении.
    if [ -f "$STAGE/control/conffiles" ]; then
        while IFS= read -r cf; do
            [ -n "$cf" ] || continue
            if [ ! -f "$STAGE/data$cf" ]; then
                echo "conffiles ссылается на $cf, которого нет в пакете" >&2
                exit 1
            fi
        done < "$STAGE/control/conffiles"
    fi
    chmod 0755 "$STAGE/control/postinst" "$STAGE/control/prerm" 2>/dev/null || true

    cp "$ROOT/ipk/debian-binary" "$STAGE/debian-binary"

    ( cd "$STAGE/control" && tar $TAR_OPTS -czf ../control.tar.gz . )
    ( cd "$STAGE/data"    && tar $TAR_OPTS -czf ../data.tar.gz    . )

    IPK="$OUT/${PKG}_${VERSION}-${REVISION}_${ARCH}.ipk"
    ( cd "$STAGE" && tar $TAR_OPTS -czf "$IPK" ./debian-binary ./control.tar.gz ./data.tar.gz )

    rm -rf "$STAGE"
    printf "  %-46s %7.1f КБ (на диске %.1f КБ)\n" \
        "$(basename "$IPK")" \
        "$(wc -c < "$IPK" | awk '{print $1/1024}')" \
        "$(echo "$SIZE" | awk '{print $1/1024}')"
done
