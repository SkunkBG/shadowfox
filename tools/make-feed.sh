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
# которые opkg берёт для скачивания и проверки, и SHA256sum — по нему
# пакет сверяет shadowfox-update: MD5 для этого давно не годится.
#
# Подпись. Индекс каждого каталога подписывается Ed25519 закрытым ключом
# из SIGN_KEY_FILE (в CI — из секрета). Без ключа фид собирается, но
# роутер такое обновление не примет — об этом громко предупреждаем.
SIGN_KEY_FILE=${SIGN_KEY_FILE:-}
if [ -n "$SIGN_KEY_FILE" ] && [ ! -r "$SIGN_KEY_FILE" ]; then
    echo "SIGN_KEY_FILE=$SIGN_KEY_FILE не читается" >&2
    exit 1
fi
if [ -n "$SIGN_KEY_FILE" ]; then
    # Ключ обязан соответствовать вшитому в пакет открытому: иначе
    # подпись верна, но роутер её отвергнет. Сверяем до подписи.
    want=$(openssl pkey -in "$SIGN_KEY_FILE" -pubout 2>/dev/null)
    have=$(cat "$ROOT/keys/shadowfox.pub")
    if [ "$want" != "$have" ]; then
        echo "закрытый ключ не парный к keys/shadowfox.pub" >&2
        exit 1
    fi
fi
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
        sha=$(openssl dgst -sha256 -r "$ipk" | cut -d' ' -f1)

        sed -e '/^$/d' "$tmp/control" >> "$dir/Packages"
        {
            echo "Filename: $(basename "$ipk")"
            echo "Size: $size"
            echo "MD5Sum: $md5"
            echo "SHA256sum: $sha"
            echo ""
        } >> "$dir/Packages"

        rm -rf "$tmp"
    done

    gzip -9 -c "$dir/Packages" > "$dir/Packages.gz"

    if [ -n "$SIGN_KEY_FILE" ]; then
        openssl pkeyutl -sign -inkey "$SIGN_KEY_FILE" -rawin \
            -in "$dir/Packages" -out "$dir/Packages.sig"
        signed=", подписан"
    else
        rm -f "$dir/Packages.sig"
        signed=", БЕЗ ПОДПИСИ"
    fi
    echo "  $(basename "$dir"): $(grep -c '^Package:' "$dir/Packages") пакет(ов)$signed"
done

[ -n "$SIGN_KEY_FILE" ] || echo "SIGN_KEY_FILE не задан: роутер такой фид не примет" >&2

# Открытый ключ рядом с фидом — для сверки вручную; роутер пользуется
# копией, вшитой в пакет.
cp "$ROOT/keys/shadowfox.pub" "$BUILD/feed/shadowfox.pub"

# Скрипт подключения кладём в корень фида, чтобы его можно было забрать
# с роутера одной командой.
cp "$ROOT/tools/add-repo.sh"  "$BUILD/feed/add-repo.sh"
cp "$ROOT/tools/uninstall.sh" "$BUILD/feed/uninstall.sh"

# Иначе GitHub Pages прогонит содержимое через Jekyll и может выкинуть
# часть файлов.
: > "$BUILD/feed/.nojekyll"
