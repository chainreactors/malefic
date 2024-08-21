FROM rust:1.80-bullseye
SHELL ["/bin/bash", "-c"]

RUN sed -i 's/http:\/\/deb.debian.org/https:\/\/mirrors.163.com/g' /etc/apt/sources.list
# install basic tools
RUN apt update \
    && apt install -y vim curl git wget mingw-w64 build-essential protobuf-compiler gcc-multilib clang cmake make libssl-dev lzma-dev libxml2-dev \
    && apt clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

RUN rustup default nightly-2024-08-16 && \
    rustup target add x86_64-pc-windows-gnu && \
    rustup target add i686-pc-windows-gnu && \
    rustup target add x86_64-unknown-linux-gnu && \
    rustup target add i686-unknown-linux-gnu && \
    rustup target add x86_64-apple-darwin && \
    rustup target add aarch64-apple-darwin

WORKDIR /build
RUN git clone --depth=1 https://github.com/tpoechtrager/osxcross.git
WORKDIR /build/osxcross/tarballs
RUN wget https://github.com/phracker/MacOSX-SDKs/releases/download/11.3/MacOSX11.3.sdk.tar.xz
# build osxcross
WORKDIR /build/osxcross
RUN UNATTENDED=yes OSX_VERSION_MIN=10.13 ./build.sh
# 创建符号链接
RUN ln -s /build/osxcross/target/SDK/MacOSX11.3.sdk/System/ /System
# 设置 PATH
ENV PATH="$PATH:/build/osxcross/target/bin"