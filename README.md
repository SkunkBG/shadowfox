# Shadow Fox

Менеджер Xray и доменной маршрутизации для роутеров Keenetic. Один статический
бинарник на C, без зависимостей кроме libc, под все архитектуры Keenetic.

Заменяет связку `neofit` + отдельный демон маршрутизации: xray слушает SOCKS5 на
localhost, штатный компонент Keenetic «Прокси-клиент» поднимает поверх него
интерфейс `Proxy0`, а домены и подсети из конфигов заворачиваются в этот
интерфейс через ipset и fwmark.

```
домены/CIDR → ipset → fwmark → ip rule → Proxy0 → xray socks5 → VLESS
```

## Состояние

Этап 1 из 5: каркас сборки и упаковки. Демон запускается, читает конфиг,
корректно обрабатывает сигналы и переживает `opkg upgrade`. Маршрутизации и
управления xray пока нет — см. [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Сборка

Кросс-компиляторы musl под macOS не существуют, поэтому локально доступны только
юнит-тесты, а бинарники под роутер собираются в контейнере или в CI.

```bash
make check        # юнит-тесты, работают и на macOS
make docker-all   # бинарники и пакеты в контейнере
make feed         # opkg-фид в build/feed
make help         # все цели
```

Если тулчейны musl уже есть в `PATH`:

```bash
make all          # aarch64, mipsel, mips
make ipk-all
```

## Ядро Xray

Xray написан на Go и кросс-компилируется без сторонних тулчейнов — нужен
только `brew install go`. Собирается отдельной командой, потому что это
чужой апстрим с закреплённой версией:

```bash
make xray-sizes                # три варианта × три архитектуры, таблица размеров
make xray VARIANT=minimal      # только нужный вариант
make xray-ipk VARIANT=minimal  # упаковать в .ipk
```

Пакет ставится в `/opt/sbin/shadowfox-xray`, а не в `/opt/sbin/xray`, чтобы
не конфликтовать со штатным `xray-core` из Entware.

## Установка на роутер

> **Текущее состояние — каркас.** Демон запускается, читает конфиг и
> отвечает на сигналы. Он **не управляет xray и не трогает маршрутизацию**.
> Установка сейчас проверяет упаковку и автозапуск, не более.

Подключить фид и поставить пакет:

```bash
curl -Ls https://skunkbg.github.io/shadowfox/add-repo.sh | sh
opkg update && opkg install shadowfox
```

Управление — через симлинк `shadowfox`, созданный при установке:

```bash
shadowfox start | stop | restart | status
```

Обновить после новой сборки:

```bash
opkg update && opkg upgrade shadowfox
```

Каждый прогон CI выпускает пакет с новой ревизией (`0.1.0-<номер прогона>`),
поэтому opkg видит обновление. Если бы версия не менялась, он считал бы
пакет уже установленным и молча ничего не делал.

Удалить полностью — вместе с настройками, журналом и подключённым фидом:

```bash
curl -Ls https://skunkbg.github.io/shadowfox/uninstall.sh | sh
```

Одного `opkg remove shadowfox` для установки начисто мало: файлы настроек
объявлены как `conffiles` и переживают удаление, а журнал и запись о
репозитории пакету не принадлежат вовсе.

## Соседство с HydraRoute

Пакеты не пересекаются ни одним файлом и спокойно стоят рядом:

| | HydraRoute Neo | Shadow Fox |
|---|---|---|
| настройки | `/opt/etc/HydraRoute/` | `/opt/etc/shadowfox/` |
| автозапуск | `S99hrneo` | `S99shadowfox` |
| ndm-хуки | `015-hrneo.sh` | `015-shadowfox.sh` |
| команда | `/opt/bin/neo` | `/opt/bin/shadowfox` |

Конфликт начнётся на этапе 4, когда Shadow Fox станет править netfilter и
управлять xray — тем же, чем сейчас владеет HydraRoute: `hrneo` держит
ipset, метки и правила маршрутизации, а `hrweb` — `/opt/etc/xray/config.json`
и службу `S24xray`. Два хозяина у одних и тех же правил работать не будут,
и к тому моменту нужно будет выбрать один.

До тех пор Shadow Fox ничего из этого не касается.

## Файлы

| Путь | Назначение |
|---|---|
| `/opt/bin/shadowfoxd` | демон |
| `/opt/etc/shadowfox/shadowfox.conf` | параметры демона |
| `/opt/etc/shadowfox/domain.conf` | домены и целевые интерфейсы |
| `/opt/etc/shadowfox/ip.list` | статические подсети |
| `/opt/etc/init.d/S99shadowfox` | автозапуск |
| `/opt/etc/ndm/netfilter.d/015-shadowfox.sh` | восстановление правил |
| `/opt/etc/ndm/ifstatechanged.d/015-shadowfox.sh` | реакция на события интерфейсов |
| `/opt/var/log/shadowfoxd.log` | журнал |
| `/opt/var/run/shadowfoxd.pid` | pid |

Все три файла в `/opt/etc/shadowfox/` объявлены как `conffiles` и переживают
обновление пакета.

## Сигналы

| Сигнал | Действие |
|---|---|
| `SIGTERM`, `SIGINT` | корректное завершение |
| `SIGHUP` | перечитать конфиг, переоткрыть журнал |
| `SIGUSR1` | восстановить правила — шлют ndm-хуки роутера |
