#!/bin/sh
# Сквозная проверка: наш генератор -> настоящий Xray.
#
# Юнит-тесты сравнивают строки и не заметят, если мы соберём формально
# корректный JSON, который Xray отвергнет по смыслу. Здесь конфиг для
# каждой формы ссылки прогоняется через `xray run -test`.
#
# Ссылки синтетические. Настоящую ссылку сюда класть нельзя: в vless://
# зашит uuid, то есть ключ доступа к серверу.
#
# Одного `-test` мало: он проверяет разбор конфига, но не то, что нужный
# модуль вкомпилирован. Поэтому многоузловой конфиг ещё и запускается.
#
# Осторожно: запуск ловит не всё. Проверено — сборка без app/observatory
# стартует на конфиге с балансировщиком leastPing без единой ошибки,
# просто балансировка молча деградирует. Такое не ловится ни -test, ни
# запуском, поэтому app/observatory обязан быть во всех вариантах distro.
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
SFD="$ROOT/build/shadowfoxd"

XRAY=""
for cand in "$ROOT"/build/xray/xray-check-* "$ROOT"/build/xray/out/xray-*; do
    [ -x "$cand" ] || continue
    # Бинарники под роутер здесь не запустить — нужен собранный под хост.
    if "$cand" version >/dev/null 2>&1; then XRAY="$cand"; break; fi
done

[ -x "$SFD" ] || { echo "нет $SFD — сначала 'make native'" >&2; exit 1; }
if [ -z "$XRAY" ]; then
    # Локально пропуск удобен, в CI — опасен: молчаливый пропуск выглядит
    # как пройденная проверка. Там выставляется SF_REQUIRE_XRAY=1.
    if [ "${SF_REQUIRE_XRAY:-0}" = "1" ]; then
        echo "нет собранного под эту машину Xray, а он требуется" >&2
        exit 1
    fi
    echo "пропуск: нет собранного под эту машину Xray (xray/check.sh)" >&2
    exit 0
fi

UUID=d342d11e-d424-4583-b36e-524ab1f0afa4
PBK=yZ8kPCPPnGVJTIPMQYWvVIeLTHRGb2pDeSCLZlnzWXA

# Имя формы | ссылка
CASES=$(cat <<CASES
tcp+reality|vless://$UUID@example.com:443?type=tcp&security=reality&pbk=$PBK&fp=chrome&sni=www.google.com&sid=6ba85179e30d4fc2&spx=%2F&flow=xtls-rprx-vision&encryption=none#reality
tcp+tls+alpn|vless://$UUID@example.com:443?type=tcp&security=tls&sni=example.com&alpn=h2%2Chttp%2F1.1&fp=firefox#tls
ws+tls|vless://$UUID@example.com:443?type=ws&security=tls&sni=cdn.example.com&path=%2Fws&host=cdn.example.com#ws
grpc+tls|vless://$UUID@example.com:443?type=grpc&security=tls&sni=example.com&serviceName=gsvc#grpc
xhttp+reality|vless://$UUID@example.com:443?type=xhttp&security=reality&pbk=$PBK&sni=www.google.com&path=%2Fx#xhttp
tcp+http-header|vless://$UUID@example.com:80?type=tcp&headerType=http&host=example.com#httphdr
plain|vless://$UUID@example.com:443#plain
CASES
)

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# Запускает Xray на пару секунд и убеждается, что он не умер сразу.
# Ловит то, чего не видит -test: незарегистрированные приложения.
run_briefly() {
    cfg=$1
    "$XRAY" run -c "$cfg" > "$tmp/run.log" 2>&1 &
    pid=$!
    sleep 2
    if kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null
        wait "$pid" 2>/dev/null || true
        return 0
    fi
    wait "$pid" 2>/dev/null || true
    cat "$tmp/run.log"
    return 1
}

fails=0
echo "проверяю через $(basename "$XRAY")"

echo "$CASES" | while IFS='|' read -r name link; do
    [ -n "$name" ] || continue

    for extra in "" "--no-fragment"; do
        cfg="$tmp/$name.json"
        # shellcheck disable=SC2086
        if ! "$SFD" --link "$link" $extra > "$cfg" 2>"$tmp/err"; then
            printf '  ПРОВАЛ %-16s %s не разобрана: %s\n' \
                "$name" "${extra:-с фрагментацией}" "$(cat "$tmp/err")"
            fails=$((fails + 1))
            continue
        fi

        if out=$("$XRAY" run -test -c "$cfg" 2>&1) &&
           echo "$out" | grep -q "Configuration OK"; then
            printf '  ok     %-16s %s\n' "$name" "${extra:-с фрагментацией}"
        else
            printf '  ПРОВАЛ %-16s %s\n%s\n' "$name" "${extra:-с фрагментацией}" "$out"
            fails=$((fails + 1))
        fi
    done

    [ "$fails" -eq 0 ] || exit 1
done

# Многоузловая подписка: балансировщик и наблюдатель. Проверяется и
# разбором, и настоящим запуском.
sub="$tmp/sub.txt"
cat > "$sub" <<SUB
vless://$UUID@a.example.com:443?type=tcp&security=reality&pbk=$PBK&sni=www.google.com&sid=aa&fp=chrome#Первый
vless://$UUID@b.example.com:8443?type=ws&security=tls&sni=b.example.com&path=%2Fws#Второй
vless://$UUID@c.example.com:443?type=grpc&security=tls&sni=c.example.com&serviceName=g#Третий
SUB

cfg="$tmp/multi.json"
if ! "$SFD" --sub "$sub" > "$cfg" 2>/dev/null; then
    echo "  ПРОВАЛ multi            подписка не разобрана"
    exit 1
fi

if out=$("$XRAY" run -test -c "$cfg" 2>&1) &&
   echo "$out" | grep -q "Configuration OK"; then
    printf '  ok     %-16s разбор\n' "multi+balancer"
else
    printf '  ПРОВАЛ %-16s разбор\n%s\n' "multi+balancer" "$out"
    exit 1
fi

if run_briefly "$cfg"; then
    printf '  ok     %-16s запуск\n' "multi+balancer"
else
    printf '  ПРОВАЛ %-16s запуск\n' "multi+balancer"
    exit 1
fi
