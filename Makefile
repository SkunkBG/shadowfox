PROJECT  = shadowfoxd
PKG      = shadowfox
VERSION  = 0.1.0
REVISION = 1

# Кросс-компиляторы musl. На macOS их нет — собирай через `make docker-all`
# или в CI. Локально доступна только цель `native` для юнит-тестов.
#
# Имена берём первое доступное из списка: у сборок cross-tools/musl-cross
# префикс с "unknown", у старых с musl.cc — без него. Так работает и то,
# что уже стоит на машине, и то, что ставит fetch-toolchains.sh.
pick_cc = $(firstword $(foreach c,$(1),$(if $(shell command -v $(c) 2>/dev/null),$(c))) $(firstword $(1)))

CC_AARCH64 = $(call pick_cc,aarch64-unknown-linux-musl-gcc aarch64-linux-musl-gcc)
CC_MIPSEL  = $(call pick_cc,mipsel-unknown-linux-muslsf-gcc mipsel-linux-muslsf-gcc)
CC_MIPS    = $(call pick_cc,mips-unknown-linux-muslsf-gcc mips-linux-muslsf-gcc)
CC_NATIVE  = cc

# -fstack-protector-strong: демон от root разбирает пакеты из сети;
# разборщики проверены, но защита в глубину стоит десятков байт на
# функцию. _FORTIFY_SOURCE не включаем: у musl его нет.
COMMON_CFLAGS = -Os -Wall -Wextra -Wno-unused-parameter \
			-fstack-protector-strong \
			-ffunction-sections -fdata-sections \
			-fno-unwind-tables -fno-asynchronous-unwind-tables \
			-fomit-frame-pointer -fno-strict-aliasing \
			-D_GNU_SOURCE -DVERSION=\"$(VERSION)-$(REVISION)\" \
			-Iinclude

# Жёсткие предупреждения только для локальной сборки: у кросс-тулчейнов
# другой набор диагностик, и ломать на них CI смысла нет.
NATIVE_EXTRA_CFLAGS = -g -Werror -Wshadow -Wpointer-arith -Wcast-qual

COMMON_LDFLAGS = -Wl,--gc-sections -s

CFLAGS_AARCH64 = $(COMMON_CFLAGS) -march=armv8-a -fno-exceptions
CFLAGS_MIPSEL  = $(COMMON_CFLAGS) -march=mips32r2 -EL -msoft-float -mno-shared
CFLAGS_MIPS    = $(COMMON_CFLAGS) -march=mips32r2 -msoft-float -mno-shared
CFLAGS_NATIVE  = $(COMMON_CFLAGS) $(NATIVE_EXTRA_CFLAGS)

LDFLAGS_STATIC = $(COMMON_LDFLAGS) -static -static-libgcc -no-pie
LDFLAGS_NATIVE =

# Страница вшивается в бинарник: пересобираем её, когда меняется исходник.
src/logopng.c: web/logo.png tools/embed.sh
	sh tools/embed.sh web/logo.png web_logo > $@

src/fontwoff.c: web/cinzel.woff2 tools/embed.sh
	sh tools/embed.sh web/cinzel.woff2 web_font > $@

src/loginjs.c: web/login.js tools/embed.sh
	sh tools/embed.sh web/login.js web_loginjs > $@

src/webpage.c: web/index.html tools/embed.sh tools/build-page.sh $(wildcard web/logo.png)
	@mkdir -p $(BUILD)
	sh tools/build-page.sh web/index.html web/logo.png > $(BUILD)/page.html
	sh tools/embed.sh $(BUILD)/page.html web_page > $@

SRCS = src/main.c src/log.c src/util.c src/config.c src/signals.c src/url.c src/jsonw.c src/node.c src/xraycfg.c src/nodelist.c src/subs.c src/xjson.c src/base64.c src/proc.c src/apply.c src/supervise.c src/watchlist.c src/ipsets.c src/routing.c src/dnsmsg.c src/dnscap.c src/snicap.c src/tcpstat.c src/engine.c src/rci.c src/status.c src/http.c src/mask.c src/webui.c src/digest.c src/ndmauth.c src/routercfg.c src/logopng.c src/fontwoff.c src/loginjs.c src/webpage.c

BUILD = build

.PHONY: all aarch64 mipsel mips native check check-configs ipk-all feed clean distclean help docker-all \
        xray xray-ipk xray-check check-gcc

all: aarch64 mipsel mips

aarch64: CC = $(CC_AARCH64)
aarch64: CFLAGS = $(CFLAGS_AARCH64)
aarch64: LDFLAGS = $(LDFLAGS_STATIC)
aarch64: $(BUILD)/$(PROJECT)-aarch64

mipsel: CC = $(CC_MIPSEL)
mipsel: CFLAGS = $(CFLAGS_MIPSEL)
mipsel: LDFLAGS = $(LDFLAGS_STATIC)
mipsel: $(BUILD)/$(PROJECT)-mipsel

mips: CC = $(CC_MIPS)
mips: CFLAGS = $(CFLAGS_MIPS)
mips: LDFLAGS = $(LDFLAGS_STATIC)
mips: $(BUILD)/$(PROJECT)-mips

native: CC = $(CC_NATIVE)
native: CFLAGS = $(CFLAGS_NATIVE)
native: LDFLAGS = $(LDFLAGS_NATIVE)
native: $(BUILD)/$(PROJECT)

$(BUILD)/$(PROJECT)-%: src/webpage.c src/logopng.c src/fontwoff.c src/loginjs.c $(SRCS) $(wildcard include/*.h) Makefile
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) $(SRCS) -o $@ $(LDFLAGS)
	@ls -l $@ | awk '{printf "  %-28s %8.1f КБ\n", "$@", $$5/1024}'

$(BUILD)/$(PROJECT): src/webpage.c $(SRCS) $(wildcard include/*.h) Makefile
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) $(SRCS) -o $@ $(LDFLAGS)

# Юнит-тесты. Работают на macOS и Linux — единственная цель, которую
# можно гонять локально без кросс-тулчейна.
#
# Зависимость от native не для запуска, а ради сборки: тесты собирают
# файлы по одному и не трогают main.c, engine.c, webui.c, signals.c,
# status.c и сгенерированные. Целиком двоичный файл с -Werror собирает
# только native, и пока его не гоняли на Linux, ошибка gcc в webui.c
# лежала незамеченной — clang её не выдаёт.
check: native
	@mkdir -p $(BUILD)
	sh tools/check-login-js.sh
	sh tools/check-update-script.sh
	$(CC_NATIVE) $(CFLAGS_NATIVE) tests/check_config.c \
		src/config.c src/util.c src/log.c -o $(BUILD)/check_config
	./$(BUILD)/check_config
	$(CC_NATIVE) $(CFLAGS_NATIVE) tests/check_url.c \
		src/url.c src/util.c -o $(BUILD)/check_url
	./$(BUILD)/check_url
	$(CC_NATIVE) $(CFLAGS_NATIVE) tests/check_jsonw.c \
		src/jsonw.c -o $(BUILD)/check_jsonw
	./$(BUILD)/check_jsonw
	$(CC_NATIVE) $(CFLAGS_NATIVE) tests/check_node.c \
		src/node.c src/xraycfg.c src/xjson.c src/nodelist.c src/base64.c \
		src/jsonw.c src/url.c src/util.c \
		-o $(BUILD)/check_node
	./$(BUILD)/check_node
	$(CC_NATIVE) $(CFLAGS_NATIVE) tests/check_nodelist.c \
		src/nodelist.c src/base64.c src/node.c src/xraycfg.c src/xjson.c src/jsonw.c \
		src/url.c src/util.c -o $(BUILD)/check_nodelist
	./$(BUILD)/check_nodelist
	$(CC_NATIVE) $(CFLAGS_NATIVE) tests/check_xjson.c \
		src/xjson.c src/xraycfg.c src/nodelist.c src/node.c src/base64.c src/url.c \
		src/jsonw.c src/util.c -o $(BUILD)/check_xjson
	./$(BUILD)/check_xjson
	$(CC_NATIVE) $(CFLAGS_NATIVE) tests/check_subs.c \
		src/subs.c src/base64.c src/proc.c src/util.c src/log.c -o $(BUILD)/check_subs
	./$(BUILD)/check_subs
	$(CC_NATIVE) $(CFLAGS_NATIVE) tests/check_apply.c \
		src/apply.c src/proc.c src/util.c src/log.c -o $(BUILD)/check_apply
	./$(BUILD)/check_apply
	$(CC_NATIVE) $(CFLAGS_NATIVE) tests/check_tcpstat.c \
		src/tcpstat.c -o $(BUILD)/check_tcpstat
	./$(BUILD)/check_tcpstat
	$(CC_NATIVE) $(CFLAGS_NATIVE) tests/check_supervise.c \
		src/supervise.c src/util.c src/log.c -o $(BUILD)/check_supervise
	./$(BUILD)/check_supervise
	$(CC_NATIVE) $(CFLAGS_NATIVE) tests/check_watchlist.c \
		src/watchlist.c src/util.c -o $(BUILD)/check_watchlist
	./$(BUILD)/check_watchlist
	$(CC_NATIVE) $(CFLAGS_NATIVE) tests/check_ipsets.c \
		src/ipsets.c src/watchlist.c src/proc.c src/util.c src/log.c \
		-o $(BUILD)/check_ipsets
	./$(BUILD)/check_ipsets
	$(CC_NATIVE) $(CFLAGS_NATIVE) tests/check_routing.c \
		src/routing.c src/watchlist.c src/proc.c src/util.c src/log.c \
		-o $(BUILD)/check_routing
	./$(BUILD)/check_routing
	$(CC_NATIVE) $(CFLAGS_NATIVE) tests/check_dnsmsg.c \
		src/dnsmsg.c -o $(BUILD)/check_dnsmsg
	./$(BUILD)/check_dnsmsg
	$(CC_NATIVE) $(CFLAGS_NATIVE) tests/check_dnscap.c \
		src/dnscap.c src/dnsmsg.c src/util.c src/log.c \
		-o $(BUILD)/check_dnscap
	./$(BUILD)/check_dnscap
	$(CC_NATIVE) $(CFLAGS_NATIVE) tests/check_mask.c \
		src/mask.c src/util.c -o $(BUILD)/check_mask
	./$(BUILD)/check_mask
	$(CC_NATIVE) $(CFLAGS_NATIVE) tests/check_snicap.c \
		src/snicap.c src/util.c src/log.c \
		-o $(BUILD)/check_snicap
	./$(BUILD)/check_snicap
	$(CC_NATIVE) $(CFLAGS_NATIVE) tests/check_rci.c \
		src/rci.c src/util.c src/log.c -lpthread -o $(BUILD)/check_rci
	./$(BUILD)/check_rci
	$(CC_NATIVE) $(CFLAGS_NATIVE) tests/check_http.c \
		src/http.c src/util.c src/log.c -lpthread -o $(BUILD)/check_http
	./$(BUILD)/check_http
	$(CC_NATIVE) $(CFLAGS_NATIVE) tests/check_digest.c \
		src/digest.c -o $(BUILD)/check_digest
	./$(BUILD)/check_digest
	$(CC_NATIVE) $(CFLAGS_NATIVE) tests/check_ndmauth.c \
		src/ndmauth.c src/digest.c src/util.c src/log.c -o $(BUILD)/check_ndmauth
	./$(BUILD)/check_ndmauth
	$(CC_NATIVE) $(CFLAGS_NATIVE) tests/check_routercfg.c \
		src/routercfg.c src/util.c -o $(BUILD)/check_routercfg
	./$(BUILD)/check_routercfg

# Те же проверки, но компилятором из сборочного процесса. У clang и gcc
# разные наборы предупреждений, а с -Werror чужое предупреждение — это
# отказ сборки. За один день так упало четыре сборки подряд: усечение
# строки при UTF-8, буфер под %u и забытый заголовок. Все три — настоящие
# ошибки, но узнавать о них через трёхминутную сборку дорого.
#
# gcc берётся из Homebrew: системный cc на macOS — это clang.
check-gcc:
	@g=$$(ls /opt/homebrew/bin/gcc-[0-9]* /usr/local/bin/gcc-[0-9]* 2>/dev/null \
	      | sort -V | tail -1); \
	 [ -n "$$g" ] || { echo "нет gcc — поставь: brew install gcc" >&2; exit 1; }; \
	 echo "проверяю через $$g"; \
	 $(MAKE) check CC_NATIVE=$$g

ipk-all: all
	VERSION=$(VERSION) REVISION=$(REVISION) PKG=$(PKG) PROJECT=$(PROJECT) \
		sh tools/build-ipk.sh aarch64 mipsel mips

# Ядро в фид не собирается: оно приезжает выпуском, см. .github/workflows.
# Если рядом уже лежат его пакеты, make-feed.sh подхватит их сам.
feed: ipk-all
	sh tools/make-feed.sh

docker-all:
	docker build -t shadowfox-build -f tools/Dockerfile . \
		&& docker run --rm -v "$$PWD:/w" -w /w shadowfox-build make all ipk-all

# Сквозная проверка: конфиги нашего генератора скармливаются настоящему
# Xray. Юнит-тесты сравнивают строки и не заметят формально корректный
# JSON, который Xray отвергнет по смыслу.
check-configs: native
	sh tools/check-configs.sh

# Ядро Xray собирается отдельно: это Go, он кросс-компилируется сам,
# без musl-тулчейнов. Нужен только `brew install go`.
xray:
	sh xray/build.sh

# Функциональная проверка: сборка обязана принять эталонный конфиг.
# Только размеры мерить мало — можно молча потерять загрузчик.
xray-check:
	sh xray/check.sh

xray-ipk: xray xray-check
	sh xray/build-ipk.sh

# Исходники Xray не трогаем: это клон апстрима на сотни мегабайт, и
# сносить его ради пересборки демона — значит качать заново.
clean:
	find $(BUILD) -mindepth 1 -maxdepth 1 ! -name xray -exec rm -rf {} + 2>/dev/null || true
	rm -rf $(BUILD)/xray/out $(BUILD)/xray/xray-check 2>/dev/null || true

# Полная очистка, включая клон Xray. chmod нужен потому, что git и Go
# оставляют файлы без права записи, и rm -rf на них спотыкается.
distclean:
	chmod -R u+w $(BUILD) 2>/dev/null || true
	rm -rf $(BUILD)

help:
	@echo "Цели:"
	@echo "  make check       юнит-тесты (работает на macOS)"
	@echo "  make check-gcc   то же компилятором из сборки, а не clang"
	@echo "  make check-configs  прогнать сгенерированные конфиги через Xray"
	@echo "  make all         бинарники под aarch64, mipsel, mips"
	@echo "  make ipk-all     собрать .ipk под все три архитектуры"
	@echo "  make feed        собрать opkg-фид в build/feed"
	@echo "  make docker-all  всё то же в контейнере, если нет тулчейнов"
	@echo "  make xray        собрать ядро xray под три архитектуры"
	@echo "  make xray-check  проверить, что сборка принимает эталонный конфиг"
	@echo "  make xray-ipk    упаковать xray в .ipk"
	@echo "  make clean       удалить сборки, сохранив клон Xray"
	@echo "  make distclean   удалить build/ целиком"
