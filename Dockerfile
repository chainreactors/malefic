FROM ubuntu:latest

RUN sed -i 's/archive.ubuntu.com/mirrors.aliyun.com/g' /etc/apt/sources.list && \
    apt update && \
    apt install -y vim curl mingw-w64 build-essential protobuf-compiler

ARG RUST_VERSION=nightly
ENV RUSTUP_DIST_SERVER=https://mirrors.ustc.edu.cn/rust-static
ENV RUSTUP_UPDATE_ROOT=https://mirrors.ustc.edu.cn/rust-static/rustup
ENV PATH=$PATH:/root/.cargo/bin
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && \
    . "$HOME/.cargo/env" && \
    rustup default nightly && \
    rustup toolchain install nightly-2023-12-12 && \
    rustup target add x86_64-pc-windows-gnu && \
    rustup target add i686-pc-windows-gnu && \
    rustup target add x86_64-unknown-linux-gnu && \
    rustup target add i686-unknown-linux-gnu && \
    rustup target add x86_64-apple-darwin && \
    rustup target add aarch64-apple-darwin
