# Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

FROM ubuntu:22.04

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
 # GCC.
 && apt-get install -y --no-install-recommends g++ gcc \
 # LLVM toolchain.
 && echo 'deb http://apt.llvm.org/jammy/ llvm-toolchain-jammy-17 main' >> /etc/apt/sources.list.d/llvm17.list \
 && echo 'deb-src http://apt.llvm.org/jammy/ llvm-toolchain-jammy-17 main' >> /etc/apt/sources.list.d/llvm17.list \
 && curl https://apt.llvm.org/llvm-snapshot.gpg.key -o /etc/apt/trusted.gpg.d/llvm.asc \
 && apt-get update \
 && apt-get install -y --no-install-recommends llvm-17-dev clang-17 libclang-17-dev clang-format-17 clang-tidy-17 libclang-rt-17-dev \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*
