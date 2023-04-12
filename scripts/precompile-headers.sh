#!/bin/sh
#
# Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

set -o errexit
set -o nounset

BINDIR=$(dirname "$0")
while [ $# -ne 0 ]; do
    case "$1" in
        --bindir) BINDIR=$2; shift 2;;
    esac
done

HILTI_CONFIG=${BINDIR}/hilti-config
SPICY_CONFIG=${BINDIR}/spicy-config

for config in "${HILTI_CONFIG}" "${SPICY_CONFIG}"; do
    if [ ! -x "${config}" ]; then
        echo "${config} is not an executable file"
        exit 1
    fi
done

# Helper function to from a given Spicy `*-config` executable determine the location of a header.
search_header() {
    config=$1
    header=$2;

    for flag in $(${config} --cxxflags); do
        if ! echo "${flag}" | grep -q '^-I'; then
            continue
        fi
        dir=${flag#??}
        if [ -e "${dir}/${header}" ]; then
            location=${dir}/${header}
        fi
    done

    if [ -z "${location+x}" ]; then
        echo "Error: could not determine location of ${header}"
        exit 1
    fi

    echo "${location}"
}

LIBHILTI=$(search_header "${HILTI_CONFIG}" hilti/rt/libhilti.h)
LIBSPICY=$(search_header "${SPICY_CONFIG}" spicy/rt/libspicy.h)

# Extract version from `hilti-config`. It should be identical to the one from `spicy-config`.
VERSION=$(${HILTI_CONFIG} --version | cut -d ' ' -f1)

# The cache is read from the environment variable `SPICY_CACHE`
# if set; else a patch under the user's home directory is used.
CACHE=${SPICY_CACHE:-$HOME/.cache/spicy/${VERSION}}

rm -rf "${CACHE}"
mkdir -p "${CACHE}"

# NOTE: The compiler invocations here should be kept in sync
# with what we do in `CMakeLists.txt`.
cp "${LIBHILTI}" "${CACHE}/precompiled_libhilti_debug.h"
$("${HILTI_CONFIG}" --cxx --cxxflags --debug) -x c++-header "${LIBHILTI}" -o "${CACHE}/precompiled_libhilti_debug.h.gch"

cp "${LIBHILTI}" "${CACHE}/precompiled_libhilti.h"

$("${HILTI_CONFIG}" --cxx --cxxflags) -x c++-header "${LIBHILTI}" -o "${CACHE}/precompiled_libhilti.h.gch"

cp "${LIBSPICY}" "${CACHE}/precompiled_libspicy_debug.h"
$("${SPICY_CONFIG}" --cxx --cxxflags --debug) -x c++-header "${LIBSPICY}" -o "${CACHE}/precompiled_libspicy_debug.h.gch"

cp "${LIBSPICY}" "${CACHE}/precompiled_libspicy.h"
$("${SPICY_CONFIG}" --cxx --cxxflags) -x c++-header "${LIBSPICY}" -o "${CACHE}/precompiled_libspicy.h.gch"
