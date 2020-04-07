#! /bin/sh

if [ "$1" = "--release" ]; then
    debug=""
    shift
else
    debug="--debug"
fi
