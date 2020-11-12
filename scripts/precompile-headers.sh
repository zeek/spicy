#!/bin/sh

set -o errexit
set -o nounset

while [ $# -ne 0 ]; do
    case "$1" in
        --hilti-config) HILTI_CONFIG=$2; shift 2;;
    esac
done

if [ -z "${HILTI_CONFIG+x}" ]; then
    BIN=$(dirname "$0")/
    HILTI_CONFIG=${BIN}/hilti-config
fi

if [ ! -x "${HILTI_CONFIG}" ]; then
    echo "cannot determine path 'hilti-config'"
    exit 1
fi

for flag in $(${HILTI_CONFIG} --cxxflags); do
    if ! echo "${flag}" | grep -q '^-I'; then
        continue
    fi
    dir=${flag#??}
    if [ -e "${dir}"/hilti/rt/libhilti.h ]; then
        LIBHILTI=${dir}/hilti/rt/libhilti.h
    fi
done

if [ -z "${LIBHILTI+x}" ]; then
    echo "Error: could not determine location of libhilti.h"
    exit 1
fi

VERSION=$(${HILTI_CONFIG} --version | cut -d ' ' -f1)

# The cache is read from the environment variable `SPICY_CACHE`
# if set; else a patch under the user's home directory is used.
CACHE=${SPICY_CACHE:-$HOME/.cache/spicy/${VERSION}}

echo "Clearing cache directory $CACHE"
rm -rf "${CACHE}"
mkdir -p "${CACHE}"

# NOTE: The compiler invocation here should be kept in sync
# with what we do in `hilti/runtime/CMakeLists.txt`.
cp "${LIBHILTI}" "${CACHE}/precompiled_libhilti_debug.h"
echo "Creating ${CACHE}/precompiled_libhilti_debug.h.pch"
$("${HILTI_CONFIG}" --cxx --cxxflags --debug) -x c++-header "${LIBHILTI}" -o "${CACHE}/precompiled_libhilti_debug.h.pch"

cp "${LIBHILTI}" "${CACHE}/precompiled_libhilti.h"
echo "Creating ${CACHE}/precompiled_libhilti.h.pch"
$("${HILTI_CONFIG}" --cxx --cxxflags) -x c++-header "${LIBHILTI}" -o "${CACHE}/precompiled_libhilti.h.pch"
