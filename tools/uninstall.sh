#!/bin/sh
# Полностью убирает Shadow Fox с роутера, вместе с настройками,
# журналом и подключённым фидом.
#
#   curl -Ls https://skunkbg.github.io/shadowfox/uninstall.sh | sh
#
# `opkg remove` сам по себе оставляет за собой изменённые файлы настроек
# (они объявлены как conffiles), журнал и запись о репозитории. Для
# установки начисто этого мало.

echo "останавливаю службу"
/opt/etc/init.d/S99shadowfox stop >/dev/null 2>&1

echo "удаляю пакет"
opkg remove shadowfox >/dev/null 2>&1

echo "подчищаю остатки"
rm -rf /opt/etc/shadowfox
rm -f  /opt/bin/shadowfox /opt/bin/shadowfoxd
rm -f  /opt/etc/init.d/S99shadowfox
rm -f  /opt/etc/ndm/netfilter.d/015-shadowfox.sh
rm -f  /opt/etc/ndm/ifstatechanged.d/015-shadowfox.sh
rm -f  /opt/var/log/shadowfoxd.log
rm -f  /opt/var/run/shadowfoxd.pid

# Фид отключаем последним: пока он подключён, opkg может снова
# подтянуть пакет при следующем upgrade.
rm -f /opt/etc/opkg/shadowfox.conf

echo ""
echo "готово. Проверка, что ничего не осталось:"
left=$(ls -d /opt/etc/shadowfox /opt/bin/shadowfox* /opt/etc/init.d/S99shadowfox \
              /opt/etc/ndm/*/015-shadowfox.sh /opt/etc/opkg/shadowfox.conf 2>/dev/null)
if [ -n "$left" ]; then
    echo "$left"
else
    echo "  чисто"
fi

echo ""
echo "HydraRoute не тронут."
