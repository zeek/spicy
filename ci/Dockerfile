FROM ubuntu:eoan

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ARG zeek_packages

CMD ["sh"]
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates gnupg2 \
 # Zeek.
 && echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_19.10/ /' > /etc/apt/sources.list.d/security:zeek.list \
 && curl https://download.opensuse.org/repositories/security:/zeek/xUbuntu_19.10/Release.key | apt-key add - \
 && apt-get update \
 && apt-get install -y --no-install-recommends $zeek_packages \
 # Spicy build and test dependencies.
 && apt-get install -y --no-install-recommends git ninja-build ccache bison flex libfl-dev python3 python3-pip docker zlib1g-dev jq locales-all python3-setuptools python3-wheel make \
 && pip3 install btest pre-commit \
 # Spicy doc dependencies.
 && apt-get install -y --no-install-recommends python3-sphinx python3-sphinx-rtd-theme doxygen \
 # GCC-9.
 && apt-get install -y --no-install-recommends g++ gcc \
 # Clang-9.
 && apt-get install -y --no-install-recommends llvm-9-dev clang-9 libclang-9-dev libc++-dev libc++1 libc++abi-dev libc++abi1 \
 # Clang-10.
 && echo 'deb http://apt.llvm.org/eoan/ llvm-toolchain-eoan-10 main' >> /etc/apt/sources.list.d/llvm10.list \
 && echo 'deb-src http://apt.llvm.org/eoan/ llvm-toolchain-eoan-10 main' >> /etc/apt/sources.list.d/llvm10.list \
 && curl https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add - \
 && apt-get update \
 && apt-get install -y --no-install-recommends llvm-10-dev clang-10 libclang-10-dev clang-format-10 clang-tidy-10 \
 # Additional tools.
 && apt-get install -y --no-install-recommends docker.io vim \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

# Install a recent CMake.
WORKDIR /usr/local/cmake
RUN curl -L https://github.com/Kitware/CMake/releases/download/v3.15.0/cmake-3.15.0-Linux-x86_64.tar.gz | tar xzvf - -C /usr/local/cmake --strip-components 1
ENV PATH="/usr/local/cmake/bin:${PATH}"
