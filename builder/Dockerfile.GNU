FROM rust:1.80-bullseye
SHELL ["/bin/bash", "-c"]
COPY build-osxcross.sh /build/build-osxcross.sh
# install basic tools
RUN apt update \
    && apt install -y --no-install-recommends vim curl git wget mingw-w64 build-essential protobuf-compiler make gcc-multilib clang cmake libssl-dev lzma-dev libxml2-dev \
    && apt clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

WORKDIR /build
# pre-download projects for osxcross
RUN git clone --depth=1 https://github.com/tpoechtrager/osxcross.git && \
    git clone --depth=1 --branch 1300.6.5 https://github.com/tpoechtrager/apple-libtapi.git && \
    git clone --depth=1 --branch 986-ld64-711 https://github.com/tpoechtrager/cctools-port/ && \
    git clone --depth=1 https://github.com/tpoechtrager/xar.git && \
    wget https://github.com/phracker/MacOSX-SDKs/releases/download/11.3/MacOSX11.3.sdk.tar.xz -O /build/osxcross/tarballs/MacOSX11.3.sdk.tar.xz

ENV PATH="$PATH:/build/osxcross/target/bin"
WORKDIR /root/src