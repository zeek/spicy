#! /bin/sh
# shellcheck disable=SC2034
# `debug` is used by scripts that source this file.

if [ "$1" = "--release" ]; then
    debug=""
    shift
else
    debug="--debug"
fi
