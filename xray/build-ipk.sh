#!/bin/sh
# Пакует собранные xray/build.sh бинарники в .ipk.
#
# Ставится в /opt/sbin/shadowfox-xray, а не в /opt/sbin/xray: так пакет не
# конфликтует со штатным xray-core из Entware, и обе сборки могут стоять
# рядом, пока идёт сравнение.
#
#   xray/build-ipk.sh --version 26.7.28
set -eu

XVERSION=26.7.28
REVISION=1
ARCHES="aarch64 mipsel mips"
MAINTAINER=${MAINTAINER:-Shadow Fox}

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN_DIR="$ROOT/build/xray/out"
OUT="$ROOT/build/ipk"

while [ $# -gt 0 ]; do
    case "$1" in
        --version)  XVERSION=$2; shift 2 ;;
        --revision) REVISION=$2; shift 2 ;;
        --arch)     ARCHES=$2;   shift 2 ;;
        *) echo "неизвестный аргумент: $1" >&2; exit 2 ;;
    esac
done

opkg_arch() {
    case "$1" in
        aarch64) echo "aarch64-3.10" ;;
        mipsel)  echo "mipsel-3.4"   ;;
        mips)    echo "mips-3.4"     ;;
        *)       echo "" ;;
    esac
}

export COPYFILE_DISABLE=1
TAR_OPTS=""
tar --no-xattrs -cf /dev/null -T /dev/null 2>/dev/null && TAR_OPTS="--no-xattrs"

mkdir -p "$OUT"

for arch in $ARCHES; do
    ARCH=$(opkg_arch "$arch")
    [ -n "$ARCH" ] || { echo "неизвестная архитектура: $arch" >&2; exit 1; }

    BIN="$BIN_DIR/xray-$arch"
    [ -f "$BIN" ] || { echo "нет $BIN — сначала xray/build.sh" >&2; exit 1; }

    STAGE="$ROOT/build/xray-stage-$arch"
    rm -rf "$STAGE"
    mkdir -p "$STAGE/data/opt/sbin" "$STAGE/control"

    cp "$BIN" "$STAGE/data/opt/sbin/shadowfox-xray"
    chmod 0755 "$STAGE/data/opt/sbin/shadowfox-xray"

    SIZE=$(wc -c < "$BIN" | tr -d ' ')

    sed -e "s|@VERSION@|$XVERSION-$REVISION|g" \
        -e "s|@ARCH@|$ARCH|g" \
        -e "s|@INSTALLED_SIZE@|$SIZE|g" \
        -e "s|@MAINTAINER@|$MAINTAINER|g" \
        "$ROOT/xray/ipk/control/control.in" > "$STAGE/control/control"

    echo '2.0' > "$STAGE/debian-binary"

    ( cd "$STAGE/control" && tar $TAR_OPTS -czf ../control.tar.gz . )
    ( cd "$STAGE/data"    && tar $TAR_OPTS -czf ../data.tar.gz    . )

    IPK="$OUT/shadowfox-xray_${XVERSION}-${REVISION}_${ARCH}.ipk"
    ( cd "$STAGE" && tar $TAR_OPTS -czf "$IPK" ./debian-binary ./control.tar.gz ./data.tar.gz )

    rm -rf "$STAGE"
    printf '  %-52s %7.2f МБ\n' "$(basename "$IPK")" \
        "$(wc -c < "$IPK" | awk '{print $1/1048576}')"
done
