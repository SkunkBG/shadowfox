#!/bin/sh
# Проверяет, что обрезанная сборка Xray не потеряла ничего нужного.
#
# Появился после реального промаха: из distro был выброшен
# main/confloader/external, и бинарник перестал читать конфиг из файла —
# молча уходил на stdin и висел. Размеры при этом выглядели отлично.
# Сравнения размеров недостаточно, нужен запуск.
set -eu

VARIANT=${1:-lean}

ROOT=$(cd "$(dirname "$0")/.." && pwd)
SRC="$ROOT/build/xray/src"
BIN="$ROOT/build/xray/xray-check-$VARIANT"
REF="$ROOT/xray/testdata/reference.json"

[ -d "$SRC" ] || { echo "нет дерева Xray — сначала xray/build.sh" >&2; exit 1; }

distro_for() {
    case "$1" in
        full)      echo "" ;;
        lean)      echo "minimal"  ;;
        lean-plus) echo "standard" ;;
        *)         echo "$1" ;;
    esac
}

( cd "$SRC" && git checkout --quiet -- infra/conf main/distro/all/all.go )

distro=$(distro_for "$VARIANT")
if [ -n "$distro" ]; then
    cp "$ROOT/xray/distro/$distro.go" "$SRC/main/distro/all/all.go"
    case "$VARIANT" in
        lean|lean-plus) python3 "$ROOT/xray/trim.py" "$SRC" --variant "$VARIANT" >/dev/null ;;
    esac
fi

# Собираем под текущую машину, а не под роутер: проверка функциональная,
# и запустить её надо здесь.
( cd "$SRC" && CGO_ENABLED=0 go build -trimpath -buildvcs=false \
    -ldflags="-s -w" -o "$BIN" ./main )

( cd "$SRC" && git checkout --quiet -- infra/conf main/distro/all/all.go )

out=$("$BIN" run -test -c "$REF" 2>&1) || {
    echo "$out"
    echo "ПРОВАЛ: $VARIANT не принял эталонный конфиг" >&2
    exit 1
}

case "$out" in
    *"Configuration OK"*) ;;
    *) echo "$out"; echo "ПРОВАЛ: нет 'Configuration OK'" >&2; exit 1 ;;
esac

# Отдельно ловим тихий уход на stdin: конфиг при этом не читается,
# а сообщение остаётся информационным, без ненулевого кода возврата.
case "$out" in
    *"reading from stdin"*)
        echo "$out"
        echo "ПРОВАЛ: конфиг не прочитан из файла" >&2
        exit 1 ;;
esac

echo "$VARIANT: эталонный конфиг принят"
