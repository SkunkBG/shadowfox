#!/bin/sh
# Собирает Xray-core под архитектуры Keenetic и печатает размеры:
# как есть и после сжатия.
#
# Сжатый размер важнее: внутренний раздел Keenetic — UBIFS, он жмёт
# содержимое прозрачно, поэтому Installed-Size из пакета не равен расходу
# флеша. gzip -6 берём как консервативную модель.
#
# Апстрим собирается без изменений. Раньше здесь были урезанные варианты
# (lean, lean-plus): xray/trim.py вырезал из infra/conf и distro лишние
# протоколы и снимал 20% сжатого размера — около двух мегабайт флеша
# после сжатия UBIFS. От них отказались: обрезка правила исходники
# апстрима и ломалась на его обновлениях, а главное — умела ломать
# поведение тихо. Проверено: сборка без app/observatory стартует на
# конфиге с балансировщиком без единой ошибки, балансировка при этом
# молча деградирует. Ни `run -test`, ни запуск этого не видят. Для ядра,
# через которое идёт весь трафик, два мегабайта такого размена не стоят.
#
#   xray/build.sh
#   xray/build.sh --arch aarch64
#   xray/build.sh --version v26.7.28
set -eu

XRAY_VERSION=v26.7.28
ARCHES="aarch64 mipsel mips"

ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK="$ROOT/build/xray"
SRC="$WORK/src"
OUT="$WORK/out"

while [ $# -gt 0 ]; do
    case "$1" in
        --version) XRAY_VERSION=$2; shift 2 ;;
        --arch)    ARCHES=$2;       shift 2 ;;
        -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
        *) echo "неизвестный аргумент: $1" >&2; exit 2 ;;
    esac
done

command -v go >/dev/null 2>&1 || {
    echo "нужен Go: brew install go" >&2
    exit 1
}

# GOARCH и GOMIPS под архитектуры Entware. Keenetic на MIPS идёт без
# аппаратного FPU — отсюда softfloat, он же суффикс sf в именах фида.
go_env() {
    case "$1" in
        aarch64) echo "GOARCH=arm64" ;;
        mipsel)  echo "GOARCH=mipsle GOMIPS=softfloat" ;;
        mips)    echo "GOARCH=mips   GOMIPS=softfloat" ;;
        *) echo "" ;;
    esac
}

if [ ! -d "$SRC/.git" ]; then
    echo "клонирую Xray-core $XRAY_VERSION"
    mkdir -p "$WORK"
    git clone --quiet --depth 1 --branch "$XRAY_VERSION" \
        https://github.com/XTLS/Xray-core.git "$SRC"
else
    ( cd "$SRC" && git fetch --quiet --depth 1 origin tag "$XRAY_VERSION" \
        && git checkout --quiet "$XRAY_VERSION" )
fi

# Дерево могло остаться правленым от старых сборок с обрезкой.
( cd "$SRC" && git checkout --quiet -- . )

mkdir -p "$OUT"
REPORT="$WORK/sizes.tsv"
: > "$REPORT"

for arch in $ARCHES; do
    env_vars=$(go_env "$arch")
    [ -n "$env_vars" ] || { echo "неизвестная арка $arch" >&2; exit 1; }

    bin="$OUT/xray-$arch"
    echo "собираю $arch"

    # -trimpath и -buildid= убирают из бинарника пути сборочной машины,
    # чтобы результат был воспроизводимым.
    ( cd "$SRC" && env CGO_ENABLED=0 GOOS=linux $env_vars \
        go build -trimpath -buildvcs=false \
                 -ldflags="-s -w -buildid=" \
                 -o "$bin" ./main )

    raw=$(wc -c < "$bin" | tr -d ' ')
    gz=$(gzip -6 -c "$bin" | wc -c | tr -d ' ')
    printf '%s\t%s\t%s\n' "$arch" "$raw" "$gz" >> "$REPORT"
done

echo ""
printf '%-9s %12s %14s\n' АРХ 'НА ДИСКЕ' 'ПОСЛЕ GZIP'
awk -F'\t' '{ printf "%-9s %9.2f МБ %11.2f МБ\n", $1, $2/1048576, $3/1048576 }' "$REPORT"
echo ""
echo "бинарники: $OUT"
