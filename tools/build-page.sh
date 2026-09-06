#!/bin/sh
# Готовит страницу к встраиванию: если рядом лежит web/logo.png, ставит
# его вместо нарисованного значка. Файла нет — страница идёт как есть,
# со встроенным SVG. Так сборка не зависит от наличия картинки.
set -eu

SRC=${1:-web/index.html}
LOGO=${2:-web/logo.png}

if [ ! -f "$LOGO" ]; then
    cat "$SRC"
    exit 0
fi

# base64 без переносов: у GNU это -w0, у BSD переносов нет вовсе.
if base64 --help 2>&1 | grep -q '\-w'; then
    B64=$(base64 -w0 < "$LOGO")
else
    B64=$(base64 < "$LOGO" | tr -d '\n')
fi

# Картинка тяжелее рисунка, и вся страница лежит в бинарнике: следим,
# чтобы логотип не раздул прошивку роутера незаметно.
SIZE=$(wc -c < "$LOGO" | tr -d ' ')
if [ "$SIZE" -gt 40000 ]; then
    echo "web/logo.png весит $SIZE байт — уменьши до 128×128" >&2
    exit 1
fi

awk -v img="$B64" '
    /<!--ЛОГОТИП-->/  { skip = 1
                        print "    <img class=\"mark\" alt=\"\" src=\"data:image/png;base64," img "\">"
                        next }
    /<!--\/ЛОГОТИП-->/ { skip = 0; next }
    !skip
' "$SRC"
