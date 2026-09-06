#!/bin/sh
# Скачивает кросс-тулчейны musl в $1 (по умолчанию /opt/toolchains).
#
# Берём готовые сборки из релизов cross-tools/musl-cross, а не с musl.cc:
# тот отдавал около 1 МБ/с, и три тулчейна качались больше двенадцати
# минут, регулярно упираясь в таймаут. С GitHub те же тулчейны в формате
# xz весят вдвое меньше и приходят за секунды.
#
# Версия релиза закреплена: сборочный тулчейн — часть воспроизводимости,
# и молча меняться он не должен.
set -eu

DEST=${1:-/opt/toolchains}
RELEASE=${MUSL_CROSS_RELEASE:-20260823}
BASE="https://github.com/cross-tools/musl-cross/releases/download/$RELEASE"

# Имена совпадают с именами каталогов внутри архивов и с префиксами
# компиляторов: <имя>/bin/<имя>-gcc
TOOLCHAINS="aarch64-unknown-linux-musl mipsel-unknown-linux-muslsf mips-unknown-linux-muslsf"

mkdir -p "$DEST"

for tc in $TOOLCHAINS; do
    if [ -x "$DEST/$tc/bin/$tc-gcc" ]; then
        echo "уже есть: $tc" >&2
        continue
    fi

    echo "качаю $tc" >&2
    curl -fsSL --retry 3 --retry-delay 5 -o "$DEST/$tc.tar.xz" "$BASE/$tc.tar.xz"
    tar -xJf "$DEST/$tc.tar.xz" -C "$DEST"
    rm -f "$DEST/$tc.tar.xz"

    [ -x "$DEST/$tc/bin/$tc-gcc" ] || {
        echo "после распаковки нет $DEST/$tc/bin/$tc-gcc" >&2
        exit 1
    }
done

# Печатаем PATH одной строкой — удобно и в CI, и вручную.
for tc in $TOOLCHAINS; do
    printf '%s/%s/bin:' "$DEST" "$tc"
done
echo ""
