FROM ubuntu:focal

# Increase this to force a rebuild of the Docker image (in Cirrus, in particular).
ENV IMAGE_VERSION=1

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ARG ZEEK_LTS=1
ARG ZEEK_VERSION=4.0.0-0

CMD ["sh"]
ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/opt/spicy/bin:/opt/zeek/bin:${PATH}"

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates gnupg2 less sudo \
 # Install Zeek.
 && mkdir -p /tmp/zeek-packages \
 && cd /tmp/zeek-packages \
 && if [ -n "${ZEEK_LTS}" ]; then ZEEK_LTS="-lts"; fi && export ZEEK_LTS \
 && apt-get install -y --no-install-recommends libpcap0.8 libpcap-dev libssl-dev zlib1g-dev libmaxminddb0 libmaxminddb-dev python python3 python3-pip python3-semantic-version python3-git \
 && curl -L --remote-name-all \
    https://download.zeek.org/binary-packages/xUbuntu_20.04/amd64/zeek${ZEEK_LTS}_${ZEEK_VERSION}_amd64.deb \
    https://download.zeek.org/binary-packages/xUbuntu_20.04/amd64/zeek${ZEEK_LTS}-core_${ZEEK_VERSION}_amd64.deb \
    https://download.zeek.org/binary-packages/xUbuntu_20.04/amd64/zeekctl${ZEEK_LTS}_${ZEEK_VERSION}_amd64.deb \
    https://download.zeek.org/binary-packages/xUbuntu_20.04/amd64/zeek${ZEEK_LTS}-core-dev_${ZEEK_VERSION}_amd64.deb \
    https://download.zeek.org/binary-packages/xUbuntu_20.04/amd64/libbroker${ZEEK_LTS}-dev_${ZEEK_VERSION}_amd64.deb \
    https://download.zeek.org/binary-packages/xUbuntu_20.04/amd64/zeek${ZEEK_LTS}-libcaf-dev_${ZEEK_VERSION}_amd64.deb \
 && [[ ${ZEEK_VERSION} = 4.* ]] && curl -L --remote-name-all \
    https://download.zeek.org/binary-packages/xUbuntu_20.04/amd64/zeek${ZEEK_LTS}-btest_${ZEEK_VERSION}_amd64.deb \
    https://download.zeek.org/binary-packages/xUbuntu_20.04/amd64/zeek${ZEEK_LTS}-zkg_${ZEEK_VERSION}_amd64.deb \
 ||  pip3 install --no-cache-dir "btest>=0.66" zkg \
 && dpkg -i ./*.deb \
 && cd - \
 && rm -rf /tmp/zeek-packages \
 # clang-12
 && echo 'deb http://apt.llvm.org/focal/ llvm-toolchain-focal-12 main' > /etc/apt/sources.list.d/llvm.list \
 && curl -o - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add - \
 && apt update \
 && apt install -y --no-install-recommends clang-12 \
 # Spicy build and test dependencies.
 && apt-get install -y --no-install-recommends git cmake ninja-build ccache bison flex g++ libfl-dev zlib1g-dev jq locales-all make \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/* \
 # Install a recent CMake.
 && mkdir -p /opt/cmake \
 && curl -L https://github.com/Kitware/CMake/releases/download/v3.18.0/cmake-3.18.0-Linux-x86_64.tar.gz | tar xzvf - -C /opt/cmake --strip-components 1 \
 # Configure zkg \
 && zkg autoconfig \
 && echo "@load packages" >>"$(zeek-config --site_dir)"/local.zeek

ENV PATH="/opt/zeek/bin:/opt/cmake/bin:${PATH}"
ENV LD_LIBRARY_PATH /usr/lib/llvm-12/lib/clang/12.0.1/lib/linux

WORKDIR /root
