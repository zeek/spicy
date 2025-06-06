# Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

FROM ubuntu:24.04

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
    rsync \
    zlib1g-dev \
 && apt-get install -y pipx \
 && pipx install "btest>=0.66" pre-commit \
 # Spicy doc dependencies.
 && apt-get install -y --no-install-recommends python3-sphinx python3-sphinx-rtd-theme doxygen \
 && pipx install pygments \
 # LLVM toolchain.
 && curl https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add - \
 && echo 'deb http://apt.llvm.org/noble/ llvm-toolchain-noble-20 main' >> /etc/apt/sources.list.d/llvm20.list \
 && echo 'deb-src http://apt.llvm.org/noble/ llvm-toolchain-noble-20 main' >> /etc/apt/sources.list.d/llvm20.list \
 && curl https://apt.llvm.org/llvm-snapshot.gpg.key -o /etc/apt/trusted.gpg.d/llvm.asc \
 && apt-get update \
 && apt-get install -y --no-install-recommends llvm-20-dev clang-20 libclang-20-dev clang-tidy-20 libclang-rt-20-dev \
 && update-alternatives --install /usr/bin/FileCheck FileCheck $(which FileCheck-20) 100 \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

ENV PATH=/root/.local/bin/:$PATH
