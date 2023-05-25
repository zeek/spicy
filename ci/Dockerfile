# Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

FROM ubuntu:focal

ARG ZEEK_VERSION="v5.0.5"
ARG ZEEK_CONFFLAGS="--disable-spicy"

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

CMD ["sh"]
ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/opt/spicy/bin:${PATH}"

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates gnupg2 \
 # Spicy build and test dependencies.
 && apt-get install -y --no-install-recommends \
    bison \
    ccache \
    cmake \
    doxygen \
    flex \
    g++ \
    git \
    jq \
    libfl-dev \
    libssl-dev \
    locales-all \
    make \
    ninja-build \
    python3 \
    python3-pip \
    python3-setuptools \
    python3-sphinx \
    python3-sphinx-rtd-theme \
    python3-wheel \
    zlib1g-dev \
 && pip3 install --no-cache-dir "btest>=0.66" pre-commit \
 # Spicy doc dependencies.
 && apt-get install -y --no-install-recommends python3-sphinx python3-sphinx-rtd-theme doxygen \
 && pip3 install --no-cache-dir --upgrade pygments \
 # GCC-9.
 && apt-get install -y --no-install-recommends g++ gcc \
 # Clang-9.
 && apt-get install -y --no-install-recommends llvm-9-dev clang-9 libclang-9-dev libc++-dev libc++1 libc++abi-dev libc++abi1 \
 # Clang-[10,11,12].
 && echo 'deb http://apt.llvm.org/focal/ llvm-toolchain-focal-10 main' >> /etc/apt/sources.list.d/llvm10.list \
 && echo 'deb-src http://apt.llvm.org/focal/ llvm-toolchain-focal-10 main' >> /etc/apt/sources.list.d/llvm10.list \
 && echo 'deb http://apt.llvm.org/focal/ llvm-toolchain-focal-11 main' >> /etc/apt/sources.list.d/llvm11.list \
 && echo 'deb-src http://apt.llvm.org/focal/ llvm-toolchain-focal-11 main' >> /etc/apt/sources.list.d/llvm11.list \
 && echo 'deb http://apt.llvm.org/focal/ llvm-toolchain-focal-12 main' >> /etc/apt/sources.list.d/llvm12.list \
 && echo 'deb-src http://apt.llvm.org/focal/ llvm-toolchain-focal-12 main' >> /etc/apt/sources.list.d/llvm12.list \
 && echo 'deb http://apt.llvm.org/focal/ llvm-toolchain-focal-15 main' >> /etc/apt/sources.list.d/llvm15.list \
 && echo 'deb-src http://apt.llvm.org/focal/ llvm-toolchain-focal-15 main' >> /etc/apt/sources.list.d/llvm15.list \
 && curl https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add - \
 && apt-get update \
 && apt-get install -y --no-install-recommends llvm-10-dev clang-10 libclang-10-dev clang-format-10 clang-tidy-10 \
 && apt-get install -y --no-install-recommends llvm-11-dev clang-11 libclang-11-dev clang-format-11 clang-tidy-11 \
 && apt-get install -y --no-install-recommends llvm-12-dev clang-12 libclang-12-dev clang-format-12 clang-tidy-12 \
 && apt-get install -y --no-install-recommends llvm-15-dev clang-15 libclang-15-dev clang-format-15 clang-tidy-15 libclang-rt-15-dev \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

# Install a recent CMake.
WORKDIR /usr/local/cmake
RUN curl -L https://github.com/Kitware/CMake/releases/download/v3.19.2/cmake-3.19.2-Linux-x86_64.tar.gz | tar xzvf - -C /usr/local/cmake --strip-components 1
ENV PATH="/usr/local/cmake/bin:${PATH}"
