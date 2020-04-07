FROM ubuntu:eoan

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

CMD sh

ENV DEBIAN_FRONTEND=noninteractive
ENV CCACHE_DIR=/var/spool/ccache
ENV CCACHE_HASHDIR=1
ENV CCACHE_MAXSIZE=1G

RUN apt-get update
RUN apt-get install -y docker.io curl

# Some helpers
RUN apt-get install -y vim

### Zeek

  # Dependencies
RUN apt-get install -y make gcc g++ flex bison libpcap-dev libssl-dev python-dev swig zlib1g-dev ninja-build
RUN apt-get install -y git

WORKDIR /usr/local/cmake
RUN curl -L https://github.com/Kitware/CMake/releases/download/v3.15.0/cmake-3.15.0-Linux-x86_64.tar.gz | tar xzvf - -C /usr/local/cmake --strip-components 1
ENV PATH="/usr/local/cmake/bin:${PATH}"

  # Release version - 3.0
RUN mkdir -p /opt/zeek-3.0-release/src && \
    cd /opt/zeek-3.0-release/src && \
    git clone --branch release/3.0 --recursive https://github.com/zeek/zeek.git && \
    cd zeek && \
    ./configure --prefix=/opt/zeek-3.0-release --generator=Ninja && \
    cd build && \
    ninja install && \
    cd .. && \
    rm -rf build

  # Debug version - 3.0
RUN mkdir -p /opt/zeek-3.0-debug/src && \
    cd /opt/zeek-3.0-debug/src && \
    git clone --branch release/3.0 --recursive https://github.com/zeek/zeek.git && \
    cd zeek && \
    ./configure --prefix=/opt/zeek-3.0-debug --generator=Ninja --enable-debug && \
    cd build && \
    ninja install && \
    cd .. && \
    rm -rf build

  # Release version - 3.1
RUN mkdir -p /opt/zeek-3.1-release/src && \
    cd /opt/zeek-3.1-release/src && \
    git clone --branch release/3.1 --recursive https://github.com/zeek/zeek.git && \
    cd zeek && \
    ./configure --prefix=/opt/zeek-3.1-release --generator=Ninja && \
    cd build && \
    ninja install && \
    cd .. && \
    rm -rf build

  # Debug version - 3.1
RUN mkdir -p /opt/zeek-3.1-debug/src && \
    cd /opt/zeek-3.1-debug/src && \
    git clone --branch release/3.1 --recursive https://github.com/zeek/zeek.git && \
    cd zeek && \
    ./configure --prefix=/opt/zeek-3.1-debug --generator=Ninja --enable-debug && \
    cd build && \
    ninja install && \
    cd .. && \
    rm -rf build

### Spicy

RUN apt-get -y update

  # Code
RUN apt-get install -y ninja-build ccache bison flex python3 python3-pip docker zlib1g-dev jq locales-all clang-9 libclang-9-dev
RUN pip3 install btest pre-commit

  # Still need to build clang 10 ourselves.
RUN mkdir -p /opt/clang10/src && \
    cd /opt/clang10/src && \
    git clone --branch release/10.x --single-branch --recursive https://github.com/llvm/llvm-project.git && \
    cd llvm-project && \
    mkdir build && \
    cd build && \
    cmake -DCMAKE_INSTALL_PREFIX=/opt/clang10 -DLLVM_ENABLE_PROJECTS="clang;compiler-rt;clang-tools-extra" -DLLVM_TARGETS_TO_BUILD=host -DCMAKE_BUILD_TYPE=Release -DLLVM_BUILD_LLVM_DYLIB=ON -DLLVM_LINK_LLVM_DYLIB=ON -G Ninja ../llvm && \
    ninja install && \
    cd ../.. && \
    rm -rf /opt/clang10/src

  # Docs
RUN apt-get install -y python3-sphinx python3-sphinx-rtd-theme awscli
