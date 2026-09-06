#!/bin/sh
# Собирает Xray-core с урезанным набором модулей под архитектуры Keenetic
# и печатает таблицу размеров: как есть и после сжатия.
#
# Сжатый размер важнее: внутренний раздел Keenetic — UBIFS, он жмёт
# содержимое прозрачно, поэтому Installed-Size из пакета не равен расходу
# флеша. gzip -6 берём как консервативную модель.
#
# Варианты:
#   full       апстрим без изменений — эталон для сравнения
#   lean       VLESS-клиент: distro minimal + обрезка infra/conf
#   lean-plus  то же плюс vmess, trojan, shadowsocks
#
# Обрезки только distro недостаточно: она убирает регистрацию обработчиков,
# но infra/conf ссылается на все протоколы разом. Замер на v26.2.6/aarch64:
# одна distro дала -1%, distro вместе с infra/conf — -20%.
#
#   xray/build.sh                        все варианты, все архитектуры
#   xray/build.sh --variant lean         только один вариант
#   xray/build.sh --arch aarch64
#   xray/build.sh --version v26.3.27
set -eu

# По умолчанию — ровно та версия, что лежит в фиде Entware: только так
# сравнение нашей сборки со штатной честное. Свежая на 2026-09-06: v26.3.27.
XRAY_VERSION=v26.2.6
VARIANTS="full lean lean-plus"
ARCHES="aarch64 mipsel mips"

ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK="$ROOT/build/xray"
SRC="$WORK/src"
OUT="$WORK/out"

while [ $# -gt 0 ]; do
    case "$1" in
        --version) XRAY_VERSION=$2; shift 2 ;;
        --variant) VARIANTS=$2;     shift 2 ;;
        --arch)    ARCHES=$2;       shift 2 ;;
        -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
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

DISTRO="$SRC/main/distro/all/all.go"
[ -f "$DISTRO.orig" ] || cp "$DISTRO" "$DISTRO.orig"

mkdir -p "$OUT"
REPORT="$WORK/sizes.tsv"
: > "$REPORT"

# Вариант -> файл distro. Пустая строка означает апстримный all.go.
distro_for() {
    case "$1" in
        full)      echo "" ;;
        lean)      echo "minimal"  ;;
        lean-plus) echo "standard" ;;
        *)         echo "$1" ;;
    esac
}

for variant in $VARIANTS; do
    # Обрезка правит infra/conf прямо в дереве, поэтому перед каждым
    # вариантом возвращаем его в исходное состояние.
    ( cd "$SRC" && git checkout --quiet -- infra/conf )

    distro=$(distro_for "$variant")
    if [ -z "$distro" ]; then
        cp "$DISTRO.orig" "$DISTRO"
    else
        [ -f "$ROOT/xray/distro/$distro.go" ] || {
            echo "нет файла distro для варианта $variant" >&2; exit 1; }
        cp "$ROOT/xray/distro/$distro.go" "$DISTRO"

        case "$variant" in
            lean|lean-plus)
                python3 "$ROOT/xray/trim.py" "$SRC" --variant "$variant" ;;
        esac
    fi

    for arch in $ARCHES; do
        env_vars=$(go_env "$arch")
        [ -n "$env_vars" ] || { echo "неизвестная арка $arch" >&2; exit 1; }

        bin="$OUT/xray-$variant-$arch"
        echo "собираю $variant / $arch"

        # -trimpath и -buildid= убирают из бинарника пути сборочной машины,
        # чтобы результат был воспроизводимым.
        ( cd "$SRC" && env CGO_ENABLED=0 GOOS=linux $env_vars \
            go build -trimpath -buildvcs=false \
                     -ldflags="-s -w -buildid=" \
                     -o "$bin" ./main )

        raw=$(wc -c < "$bin" | tr -d ' ')
        gz=$(gzip -6 -c "$bin" | wc -c | tr -d ' ')
        printf '%s\t%s\t%s\t%s\n' "$variant" "$arch" "$raw" "$gz" >> "$REPORT"
    done
done

cp "$DISTRO.orig" "$DISTRO"
( cd "$SRC" && git checkout --quiet -- infra/conf )

echo ""
printf '%-10s %-9s %12s %14s %10s\n' ВАРИАНТ АРХ 'НА ДИСКЕ' 'ПОСЛЕ GZIP' 'ОТ FULL'
awk -F'\t' '
    { raw[$1"/"$2]=$3; gz[$1"/"$2]=$4; order[++n]=$1"/"$2 }
    END {
        for (i = 1; i <= n; i++) {
            k = order[i]; split(k, p, "/")
            base = gz["full/" p[2]]
            delta = (base > 0 && p[1] != "full") \
                ? sprintf("-%.0f%%", (base - gz[k]) * 100 / base) : "—"
            printf "%-10s %-9s %9.2f МБ %11.2f МБ %10s\n",
                   p[1], p[2], raw[k]/1048576, gz[k]/1048576, delta
        }
    }' "$REPORT"
echo ""
echo "бинарники: $OUT"
