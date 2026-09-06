#!/bin/sh
# KeeneticOS переписывает netfilter целиком и в произвольный момент,
# стирая чужие правила. Этот хук будит демона, чтобы он их восстановил.
# Ровно этого механизма не хватало neofit — правила пропадали молча.

pidfile="/opt/var/run/shadowfoxd.pid"
[ -f "$pidfile" ] || exit 0

pid=$(cat "$pidfile" 2>/dev/null)
[ -n "$pid" ] && [ -d "/proc/$pid" ] && kill -USR1 "$pid" 2>/dev/null

exit 0
