# Воспроизводимая сборка под роутер без установки тулчейнов на хост.
# Нужна на macOS, где кросс-компиляторов musl нет в принципе.
#
#   docker build -t shadowfox-build -f tools/Dockerfile .
#   docker run --rm -v "$PWD:/w" -w /w shadowfox-build make all ipk-all
FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential ca-certificates curl gzip tar xz-utils \
 && rm -rf /var/lib/apt/lists/*

COPY tools/fetch-toolchains.sh /usr/local/bin/fetch-toolchains.sh
RUN /usr/local/bin/fetch-toolchains.sh /opt/toolchains

ENV PATH="/opt/toolchains/aarch64-linux-musl-cross/bin:/opt/toolchains/mipsel-linux-muslsf-cross/bin:/opt/toolchains/mips-linux-muslsf-cross/bin:${PATH}"

WORKDIR /w
CMD ["make", "all"]
