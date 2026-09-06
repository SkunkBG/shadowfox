#!/usr/bin/env python3
"""Обрезает разборщик JSON-конфига Xray под нужный набор протоколов.

Зачем: подмены main/distro/all/all.go недостаточно. Она убирает только
регистрацию обработчиков, а пакет infra/conf жёстко ссылается на все
протоколы разом, поэтому линковщик всё равно тащит их в бинарник вместе
с gvisor. Замер на v26.2.6/aarch64: обрезка одного distro дала -1%,
обрезка infra/conf — на порядок больше.

Правка механическая: выкинуть записи из двух карт в infra/conf/xray.go
и удалить файлы протоколов, на которые больше никто не ссылается.
"""
import argparse
import pathlib
import re
import sys

# Что оставляем в каждой сборке. Ключи — те же строки, что пишутся
# в поле "protocol" конфига Xray.
VARIANTS = {
    "lean": {
        "inbound":  {"socks", "mixed", "tunnel", "dokodemo-door"},
        "outbound": {"block", "blackhole", "direct", "freedom", "socks",
                     "vless", "dns"},
    },
    "lean-plus": {
        "inbound":  {"socks", "mixed", "tunnel", "dokodemo-door"},
        "outbound": {"block", "blackhole", "direct", "freedom", "socks",
                     "vless", "dns", "shadowsocks", "trojan", "vmess"},
    },
}

# Файл infra/conf, который можно удалить, если ни один его протокол
# не остался ни во входящих, ни в исходящих.
#
# dokodemo.go и fakedns.go сюда не входят намеренно: их типы используются
# в самом xray.go и в init.go помимо карт протоколов, поэтому удаление
# ломает сборку. Их код всё равно линкуется, и выигрыша бы не дало.
PROTOCOL_FILES = {
    "wireguard.go": {"wireguard"},
    "tun.go":       {"tun"},
    "http.go":      {"http"},
    "shadowsocks.go": {"shadowsocks"},
    "vmess.go":     {"vmess"},
    "trojan.go":    {"trojan"},
    "loopback.go":  {"loopback"},
    "hysteria.go":  {"hysteria"},
}

MAP_RE = re.compile(
    r"(?P<head>(?P<name>inboundConfigLoader|outboundConfigLoader)"
    r"\s*=\s*NewJSONConfigLoader\(ConfigCreatorCache\{\n)"
    r"(?P<body>.*?)"
    r"(?P<tail>\n\t\}, \"protocol\", \"settings\"\))",
    re.S,
)
ENTRY_RE = re.compile(r'^\s*"(?P<key>[^"]+)":')


def trim(src: pathlib.Path, variant: str) -> int:
    spec = VARIANTS[variant]
    xray_go = src / "infra" / "conf" / "xray.go"
    text = xray_go.read_text()

    kept_keys: set[str] = set()
    removed = 0

    def rewrite(m: re.Match) -> str:
        nonlocal removed
        which = "inbound" if m.group("name").startswith("inbound") else "outbound"
        keep = spec[which]

        lines = []
        for line in m.group("body").split("\n"):
            entry = ENTRY_RE.match(line)
            if entry and entry.group("key") not in keep:
                removed += 1
                continue
            if entry:
                kept_keys.add(entry.group("key"))
            lines.append(line)
        return m.group("head") + "\n".join(lines) + m.group("tail")

    new_text, count = MAP_RE.subn(rewrite, text)
    if count != 2:
        print(f"ошибка: нашёл {count} карт протоколов вместо 2 — "
              f"структура infra/conf/xray.go изменилась", file=sys.stderr)
        return 1

    xray_go.write_text(new_text)

    deleted = []
    for name, keys in PROTOCOL_FILES.items():
        if keys & kept_keys:
            continue
        for path in (src / "infra" / "conf").glob(name.replace(".go", "*.go")):
            path.unlink()
            deleted.append(path.name)

    print(f"обрезка {variant}: убрано записей {removed}, "
          f"удалено файлов {len(deleted)}")
    if deleted:
        print("  " + " ".join(sorted(deleted)))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("src", type=pathlib.Path, help="дерево Xray-core")
    ap.add_argument("--variant", required=True, choices=sorted(VARIANTS))
    args = ap.parse_args()
    return trim(args.src, args.variant)


if __name__ == "__main__":
    sys.exit(main())
