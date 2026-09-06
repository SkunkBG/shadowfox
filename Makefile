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

COMMON_CFLAGS = -Os -Wall -Wextra -Wno-unused-parameter \
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

SRCS = src/main.c src/log.c src/util.c src/config.c src/signals.c src/url.c src/jsonw.c src/node.c src/xraycfg.c src/nodelist.c src/base64.c src/proc.c src/apply.c src/supervise.c src/watchlist.c src/ipsets.c src/routing.c src/dnsmsg.c src/dnscap.c src/engine.c src/rci.c src/status.c

BUILD = build

.PHONY: all aarch64 mipsel mips native check check-configs ipk-all feed clean distclean help docker-all \
        xray xray-sizes xray-ipk xray-check

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

$(BUILD)/$(PROJECT)-%: $(SRCS) $(wildcard include/*.h) Makefile
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) $(SRCS) -o $@ $(LDFLAGS)
	@ls -l $@ | awk '{printf "  %-28s %8.1f КБ\n", "$@", $$5/1024}'

$(BUILD)/$(PROJECT): $(SRCS) $(wildcard include/*.h) Makefile
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) $(SRCS) -o $@ $(LDFLAGS)

# Юнит-тесты. Работают на macOS и Linux — единственная цель, которую
# можно гонять локально без кросс-тулчейна.
check:
	@mkdir -p $(BUILD)
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
		src/node.c src/xraycfg.c src/nodelist.c src/base64.c \
		src/jsonw.c src/url.c src/util.c \
		-o $(BUILD)/check_node
	./$(BUILD)/check_node
	$(CC_NATIVE) $(CFLAGS_NATIVE) tests/check_nodelist.c \
		src/nodelist.c src/base64.c src/node.c src/xraycfg.c src/jsonw.c \
		src/url.c src/util.c -o $(BUILD)/check_nodelist
	./$(BUILD)/check_nodelist
	$(CC_NATIVE) $(CFLAGS_NATIVE) tests/check_apply.c \
		src/apply.c src/proc.c src/util.c src/log.c -o $(BUILD)/check_apply
	./$(BUILD)/check_apply
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
	$(CC_NATIVE) $(CFLAGS_NATIVE) tests/check_rci.c \
		src/rci.c src/util.c src/log.c -lpthread -o $(BUILD)/check_rci
	./$(BUILD)/check_rci

ipk-all: all
	VERSION=$(VERSION) REVISION=$(REVISION) PKG=$(PKG) PROJECT=$(PROJECT) \
		sh tools/build-ipk.sh aarch64 mipsel mips

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
xray-sizes:
	sh xray/build.sh

xray:
	sh xray/build.sh --variant $(or $(VARIANT),full)

# Функциональная проверка: собранный вариант обязан принять эталонный
# конфиг. Только размеры мерить мало — можно молча потерять загрузчик.
xray-check:
	sh xray/check.sh $(or $(VARIANT),full)

xray-ipk: xray xray-check
	sh xray/build-ipk.sh --variant $(or $(VARIANT),full)

# Исходники Xray не трогаем: это клон апстрима на сотни мегабайт, и
# сносить его ради пересборки демона — значит качать заново.
clean:
	find $(BUILD) -mindepth 1 -maxdepth 1 ! -name xray -exec rm -rf {} + 2>/dev/null || true
	rm -rf $(BUILD)/xray/out $(BUILD)/xray/xray-check-* 2>/dev/null || true

# Полная очистка, включая клон Xray. chmod нужен потому, что git и Go
# оставляют файлы без права записи, и rm -rf на них спотыкается.
distclean:
	chmod -R u+w $(BUILD) 2>/dev/null || true
	rm -rf $(BUILD)

help:
	@echo "Цели:"
	@echo "  make check       юнит-тесты (работает на macOS)"
	@echo "  make check-configs  прогнать сгенерированные конфиги через Xray"
	@echo "  make all         бинарники под aarch64, mipsel, mips"
	@echo "  make ipk-all     собрать .ipk под все три архитектуры"
	@echo "  make feed        собрать opkg-фид в build/feed"
	@echo "  make docker-all  всё то же в контейнере, если нет тулчейнов"
	@echo "  make xray-sizes  собрать все варианты xray и сравнить размеры"
	@echo "  make xray        собрать xray (VARIANT=full|lean-plus|lean)"
	@echo "  make xray-check  проверить, что сборка принимает эталонный конфиг"
	@echo "  make xray-ipk    упаковать xray в .ipk"
	@echo "  make clean       удалить сборки, сохранив клон Xray"
	@echo "  make distclean   удалить build/ целиком"
