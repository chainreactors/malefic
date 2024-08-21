FROM rust:1.80-bullseye
SHELL ["/bin/bash", "-c"]

RUN sed -i 's/http:\/\/deb.debian.org/https:\/\/mirrors.163.com/g' /etc/apt/sources.list
# install basic tools
RUN apt update \
    && apt install -y vim curl git wget mingw-w64 build-essential protobuf-compiler gcc-multilib clang cmake make libssl-dev lzma-dev libxml2-dev \
    && apt clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

WORKDIR /build
RUN git clone --depth=1 https://github.com/tpoechtrager/osxcross.git
WORKDIR /build/osxcross/tarballs
RUN wget https://github.com/phracker/MacOSX-SDKs/releases/download/11.3/MacOSX11.3.sdk.tar.xz
# build osxcross
WORKDIR /build/osxcross
RUN UNATTENDED=yes OSX_VERSION_MIN=10.13 ./build.sh
RUN ln -s /build/osxcross/target/SDK/MacOSX11.3.sdk/System/ /System
ENV PATH="$PATH:/build/osxcross/target/bin"
WORKDIR /root/src