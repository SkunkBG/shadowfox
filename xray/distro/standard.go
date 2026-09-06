// Подменяет main/distro/all/all.go в дереве Xray-core при сборке.
// Как minimal, плюс протоколы для подключения к чужим серверам.
//
// Выброшено: wireguard (тянет gvisor), dokodemo, http, loopback, fakedns,
// geodata, metrics, reverse, observatory, commander со всеми командными
// сервисами (тянет gRPC-сервер), kcp, парсеры toml и yaml,
// подкоманды main/commands/all.
package all

import (
	// Обязательное ядро. Без этого Xray не соберётся.
	_ "github.com/xtls/xray-core/app/dispatcher"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"

	// Разрыв цикла импортов между core и internet. Убирать нельзя.
	_ "github.com/xtls/xray-core/transport/internet/tagged/taggedimpl"

	// Приложения. app/geodata не берём: маршрутизация идёт по спискам
	// доменов из shadowfox, а не по geosite/geoip из .dat.
	_ "github.com/xtls/xray-core/app/dns"
	_ "github.com/xtls/xray-core/app/log"
	// Нужен балансировщику: стратегия leastPing без наблюдателя
	// не имеет данных о задержках.
	_ "github.com/xtls/xray-core/app/observatory"
	_ "github.com/xtls/xray-core/app/policy"
	_ "github.com/xtls/xray-core/app/router"
	_ "github.com/xtls/xray-core/app/stats"

	// Прокси. Мы клиент: нужен socks на входе и vless на выходе.
	_ "github.com/xtls/xray-core/proxy/blackhole"
	_ "github.com/xtls/xray-core/proxy/dns"
	_ "github.com/xtls/xray-core/proxy/freedom"
	_ "github.com/xtls/xray-core/proxy/socks"
	_ "github.com/xtls/xray-core/proxy/shadowsocks"
	_ "github.com/xtls/xray-core/proxy/trojan"
	_ "github.com/xtls/xray-core/proxy/vless/outbound"
	_ "github.com/xtls/xray-core/proxy/vmess/outbound"

	// Транспорты.
	_ "github.com/xtls/xray-core/transport/internet/grpc"
	_ "github.com/xtls/xray-core/transport/internet/httpupgrade"
	_ "github.com/xtls/xray-core/transport/internet/reality"
	_ "github.com/xtls/xray-core/transport/internet/splithttp"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	_ "github.com/xtls/xray-core/transport/internet/tls"
	_ "github.com/xtls/xray-core/transport/internet/udp"
	_ "github.com/xtls/xray-core/transport/internet/websocket"

	_ "github.com/xtls/xray-core/transport/internet/headers/http"
	_ "github.com/xtls/xray-core/transport/internet/headers/noop"

	// Конфиг читаем только из локального JSON.
	// main/json даёт разбор формата, а confloader/external — само чтение
	// файла. Без второго Xray молча уходит читать stdin и виснет.
	_ "github.com/xtls/xray-core/main/confloader/external"
	_ "github.com/xtls/xray-core/main/json"
)
