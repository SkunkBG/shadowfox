#!/bin/sh
# Проверка shadowfox-update на временном ключе: подпись сходится,
# подмена индекса и чужой ключ отвергаются, SHA-256 пакета сверяется.
# Работает на любой машине с openssl: фид лежит в каталоге и читается
# через file://, роутер и сеть не нужны.
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
SCRIPT="$ROOT/ipk/rootfs/opt/sbin/shadowfox-update"

T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT

fail() { echo "check-update-script: $*" >&2; exit 1; }

# На macOS /usr/bin/openssl — LibreSSL без -rawin для Ed25519; тот же
# openssl, что подписывает, и проверяет.
OPENSSL=$(command -v openssl)

# Ключи для проверки — одноразовые, не те, что в keys/.
openssl genpkey -algorithm ed25519 -out "$T/key.pem" 2>/dev/null
openssl pkey -in "$T/key.pem" -pubout -out "$T/pub.pem" 2>/dev/null
openssl genpkey -algorithm ed25519 -out "$T/other.pem" 2>/dev/null
openssl pkey -in "$T/other.pem" -pubout -out "$T/other.pub" 2>/dev/null

# Фид: один «пакет» и индекс к нему.
mkdir -p "$T/feed" "$T/etc" "$T/tmp"
printf 'not really an ipk\n' > "$T/feed/shadowfox_9.9.9_all.ipk"
sha=$(openssl dgst -sha256 -r "$T/feed/shadowfox_9.9.9_all.ipk" | cut -d' ' -f1)
cat > "$T/feed/Packages" <<PK
Package: shadowfox
Version: 9.9.9
Filename: shadowfox_9.9.9_all.ipk
SHA256sum: $sha

Package: shadowfox-xray
Version: 26.7.28-1
Filename: xray.ipk
SHA256sum: 0000

PK
openssl pkeyutl -sign -inkey "$T/key.pem" -rawin -in "$T/feed/Packages" -out "$T/feed/Packages.sig"
printf 'src/gz shadowfox file://%s\n' "$T/feed" > "$T/etc/shadowfox.conf"

# Подставной opkg: только записывает, что ему дали.
mkdir -p "$T/bin"
cat > "$T/bin/opkg" <<'OP'
#!/bin/sh
echo "opkg $*" >> "${OPKG_LOG:?}"
OP
chmod 0755 "$T/bin/opkg"

run() {   # ожидаемый_код ключ аргументы…
    want=$1; key=$2; shift 2
    set +e
    out=$(SF_CONF="$T/etc/shadowfox.conf" SF_TMP="$T/tmp" SF_PUBKEY_FILE="$key" \
          SF_OPKG="$T/bin/opkg" SF_OPENSSL="$OPENSSL" OPKG_LOG="$T/opkg.log" \
          sh "$SCRIPT" "$@" 2>&1)
    rc=$?
    set -e
    [ "$rc" = "$want" ] || fail "$* → код $rc, ждали $want; вывод: $out"
    printf '%s\n' "$out"
}

out=$(run 0 "$T/pub.pem" check)
echo "$out" | grep -q '^available=9.9.9$' || fail "check не нашёл версию: $out"
echo "$out" | grep -q '^xray=26.7.28-1$'   || fail "check не нашёл ядро: $out"
echo "$out" | grep -q '^verified=1$'       || fail "check без verified: $out"

out=$(run 1 "$T/other.pub" check)
echo "$out" | grep -q '^error=подпись' || fail "чужой ключ принят: $out"

cp "$T/feed/Packages" "$T/Packages.orig"
sed -i.bak 's/^Version: 9.9.9/Version: 9.9.10/' "$T/feed/Packages"
out=$(run 1 "$T/pub.pem" check)
echo "$out" | grep -q '^error=подпись' || fail "подменённый индекс принят: $out"
cp "$T/Packages.orig" "$T/feed/Packages"

rm -f "$T/feed/Packages.sig.keep"; mv "$T/feed/Packages.sig" "$T/feed/Packages.sig.keep"
out=$(run 1 "$T/pub.pem" check)
echo "$out" | grep -q '^error=у фида нет подписи' || fail "фид без подписи принят: $out"
mv "$T/feed/Packages.sig.keep" "$T/feed/Packages.sig"

: > "$T/opkg.log"
out=$(run 0 "$T/pub.pem" upgrade)
echo "$out" | grep -q '^verified=shadowfox 9.9.9$' || fail "upgrade без verified: $out"
grep -q 'opkg install .*/shadowfox_9.9.9_all.ipk$' "$T/opkg.log" || fail "opkg не получил файл: $(cat "$T/opkg.log")"

# Пакет подменили после подписания индекса — SHA-256 не сойдётся.
printf 'tampered\n' > "$T/feed/shadowfox_9.9.9_all.ipk"
: > "$T/opkg.log"
out=$(run 1 "$T/pub.pem" upgrade)
echo "$out" | grep -q '^error=SHA-256' || fail "подменённый пакет принят: $out"
grep -q install "$T/opkg.log" && fail "opkg вызван для подменённого пакета"

# Пакета нет в индексе.
out=$(run 1 "$T/pub.pem" install nonesuch)
echo "$out" | grep -q '^error=в индексе нет пакета' || fail "несуществующий пакет: $out"

[ -z "$(ls -A "$T/tmp")" ] || fail "временные каталоги не убраны: $(ls "$T/tmp")"

echo "check-update-script: все проверки пройдены"
