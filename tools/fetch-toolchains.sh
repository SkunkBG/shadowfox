#!/bin/sh
# Скачивает кросс-тулчейны musl в $1 (по умолчанию /opt/toolchains)
# и печатает строку для PATH. Используется и в CI, и в Dockerfile.
set -eu

DEST=${1:-/opt/toolchains}
mkdir -p "$DEST"

# musl.cc периодически недоступен, поэтому держим зеркало.
MIRRORS="https://musl.cc https://more.musl.cc"

TOOLCHAINS="aarch64-linux-musl-cross mipsel-linux-muslsf-cross mips-linux-muslsf-cross"

for tc in $TOOLCHAINS; do
    if [ -d "$DEST/$tc" ]; then
        echo "уже есть: $tc" >&2
        continue
    fi

    ok=0
    for m in $MIRRORS; do
        echo "качаю $tc с $m" >&2
        if curl -fsSL --retry 3 --retry-delay 5 -o "$DEST/$tc.tgz" "$m/$tc.tgz"; then
            tar -xzf "$DEST/$tc.tgz" -C "$DEST"
            rm -f "$DEST/$tc.tgz"
            ok=1
            break
        fi
    done

    [ "$ok" = 1 ] || { echo "не удалось скачать $tc ни с одного зеркала" >&2; exit 1; }
done

for tc in $TOOLCHAINS; do
    printf '%s/%s/bin:' "$DEST" "$tc"
done
echo ""
