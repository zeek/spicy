FROM ubuntu:focal

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ARG ZEEK_LTS=1
ARG ZEEK_VERSION=4.0.2-0
ARG UID=1000
ARG GID=1000

CMD ["sh"]
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates gnupg2 sudo \
 # Zeek.
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
 && dpkg -i *.deb \
 && cd - \
 && rm -rf /tmp/zeek-packages \
 # Spicy build and test dependencies.
 && apt-get install -y --no-install-recommends git ninja-build ccache bison flex libfl-dev python3 python3-pip docker zlib1g-dev jq locales-all python3-setuptools python3-wheel make \
 && pip3 install "btest>=0.66" pre-commit \
 # Spicy doc dependencies.
 && apt-get install -y --no-install-recommends python3-sphinx python3-sphinx-rtd-theme doxygen \
 && pip3 install --upgrade pygments \
 # GCC-9.
 && apt-get install -y --no-install-recommends g++ gcc \
 # Clang-9.
 && apt-get install -y --no-install-recommends llvm-9-dev clang-9 libclang-9-dev libc++-dev libc++1 libc++abi-dev libc++abi1 \
 # Clang-10 and clang-11.
 && echo 'deb http://apt.llvm.org/focal/ llvm-toolchain-focal-10 main' >> /etc/apt/sources.list.d/llvm10.list \
 && echo 'deb-src http://apt.llvm.org/focal/ llvm-toolchain-focal-10 main' >> /etc/apt/sources.list.d/llvm10.list \
 && echo 'deb http://apt.llvm.org/focal/ llvm-toolchain-focal-11 main' >> /etc/apt/sources.list.d/llvm11.list \
 && echo 'deb-src http://apt.llvm.org/focal/ llvm-toolchain-focal-11 main' >> /etc/apt/sources.list.d/llvm11.list \
 && curl https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add - \
 && apt-get update \
 && apt-get install -y --no-install-recommends llvm-10-dev clang-10 libclang-10-dev clang-format-10 clang-tidy-10 \
 && apt-get install -y --no-install-recommends llvm-11-dev clang-11 libclang-11-dev clang-format-11 clang-tidy-11 \
 # Additional tools.
 && apt-get install -y --no-install-recommends docker.io vim \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

# Install a recent CMake.
WORKDIR /usr/local/cmake
RUN curl -L https://github.com/Kitware/CMake/releases/download/v3.19.2/cmake-3.19.2-Linux-x86_64.tar.gz | tar xzvf - -C /usr/local/cmake --strip-components 1
ENV PATH="/usr/local/cmake/bin:${PATH}"

# Add a test user to catch unintentional host modifications. This is not a
# security measure as we still allow the user to run commands as root via
# explicit `sudo`.
RUN groupadd -r test -g $GID \
 && useradd --no-log-init -m -u $UID -g test test -G sudo --password ''
USER test
