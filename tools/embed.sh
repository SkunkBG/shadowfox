#!/bin/sh
# Превращает файл в массив байтов на C, предварительно сжав его.
#
# Страница отдаётся браузеру уже сжатой: на роутере нет ни места под
# внешние файлы, ни смысла жать её при каждом запросе.
#
#   tools/embed.sh web/index.html web_page > src/webpage.c
set -eu

file=$1
name=$2

gz=$(mktemp)
trap 'rm -f "$gz"' EXIT
gzip -9 -c "$file" > "$gz"

size=$(wc -c < "$gz" | tr -d ' ')

printf '/* Создан автоматически из %s. Не править руками. */\n' "$file"
printf '#include <stddef.h>\n\n'
printf 'const unsigned char %s[] = {' "$name"

od -An -v -tu1 "$gz" | tr -s ' ' '\n' | grep -v '^$' | awk '
    { printf "%s%s,", (NR % 16 == 1 ? "\n    " : " "), $1 }
    END { print "" }'

printf '};\n'
printf 'const size_t %s_len = %s;\n' "$name" "$size"
