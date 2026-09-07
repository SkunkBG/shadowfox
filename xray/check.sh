#!/bin/sh
# Проверяет, что собранное ядро принимает эталонный конфиг.
#
# Появился после реального промаха: из distro был выброшен
# main/confloader/external, и бинарник перестал читать конфиг из файла —
# молча уходил на stdin и висел. Размеры при этом выглядели отлично.
# Сравнения размеров недостаточно, нужен запуск.
#
# Обрезки больше нет (см. xray/build.sh), но проверка осталась: она
# ловит и поломки самого апстрима, и наш эталонный конфиг.
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
SRC="$ROOT/build/xray/src"
BIN="$ROOT/build/xray/xray-check"
REF="$ROOT/xray/testdata/reference.json"

[ -d "$SRC" ] || { echo "нет дерева Xray — сначала xray/build.sh" >&2; exit 1; }

# Собираем под текущую машину, а не под роутер: проверка функциональная,
# и запустить её надо здесь.
( cd "$SRC" && CGO_ENABLED=0 go build -trimpath -buildvcs=false \
    -ldflags="-s -w" -o "$BIN" ./main )

out=$("$BIN" run -test -c "$REF" 2>&1) || {
    echo "$out"
    echo "ПРОВАЛ: ядро не приняло эталонный конфиг" >&2
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

echo "эталонный конфиг принят"
