#!/bin/sh
# Раскладывает собранные .ipk по каталогам фида Entware и строит индексы.
# На выходе build/feed можно публиковать как GitHub Pages.
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BUILD="$ROOT/build"
IPKDIR="$BUILD/ipk"
FEED="$BUILD/feed/keenetic"

# Арка opkg -> каталог фида. Названия каталогов у Entware исторически
# не совпадают с названиями архитектур: mipselsf-k3.4, но mipsel-3.4.
feed_dir() {
    case "$1" in
        aarch64-3.10) echo "aarch64-k3.10"  ;;
        mipsel-3.4)   echo "mipselsf-k3.4"  ;;
        mips-3.4)     echo "mipssf-k3.4"    ;;
        *)            echo "" ;;
    esac
}

[ -d "$IPKDIR" ] || { echo "нет $IPKDIR — сначала 'make ipk-all'" >&2; exit 1; }

rm -rf "$BUILD/feed"

for ipk in "$IPKDIR"/*.ipk; do
    [ -f "$ipk" ] || continue

    base=$(basename "$ipk")
    arch=${base##*_}
    arch=${arch%.ipk}

    dir=$(feed_dir "$arch")
    if [ -z "$dir" ]; then
        echo "не знаю каталог фида для арки $arch, пропускаю $base" >&2
        continue
    fi

    mkdir -p "$FEED/$dir"
    cp "$ipk" "$FEED/$dir/"
done

# Индекс Packages: те же поля, что в control, плюс Filename, Size и MD5Sum,
# которые opkg берёт для скачивания и проверки.
for dir in "$FEED"/*; do
    [ -d "$dir" ] || continue

    : > "$dir/Packages"

    for ipk in "$dir"/*.ipk; do
        [ -f "$ipk" ] || continue

        tmp=$(mktemp -d)
        tar -xzf "$ipk" -C "$tmp" ./control.tar.gz
        tar -xzf "$tmp/control.tar.gz" -C "$tmp" ./control

        size=$(wc -c < "$ipk" | tr -d ' ')
        if command -v md5sum >/dev/null 2>&1; then
            md5=$(md5sum "$ipk" | cut -d' ' -f1)
        else
            md5=$(md5 -q "$ipk")
        fi

        sed -e '/^$/d' "$tmp/control" >> "$dir/Packages"
        {
            echo "Filename: $(basename "$ipk")"
            echo "Size: $size"
            echo "MD5Sum: $md5"
            echo ""
        } >> "$dir/Packages"

        rm -rf "$tmp"
    done

    gzip -9 -c "$dir/Packages" > "$dir/Packages.gz"
    echo "  $(basename "$dir"): $(grep -c '^Package:' "$dir/Packages") пакет(ов)"
done

# Скрипт подключения кладём в корень фида, чтобы его можно было забрать
# с роутера одной командой.
cp "$ROOT/tools/add-repo.sh"  "$BUILD/feed/add-repo.sh"
cp "$ROOT/tools/uninstall.sh" "$BUILD/feed/uninstall.sh"

# Иначе GitHub Pages прогонит содержимое через Jekyll и может выкинуть
# часть файлов.
: > "$BUILD/feed/.nojekyll"
