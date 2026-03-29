#! /bin/sh

dynamic_loading=""

if [ "$1" = "--release" ]; then
    debug=""
    shift
else
    debug="--debug"
fi

if [ "$1" = "--dynamic-loading" ]; then
    dynamic_loading="--dynamic-loading"
    shift
fi

# Prevent MSYS from converting /flags to C:/Program Files/Git/flags.
export MSYS2_ARG_CONV_EXCL="*"

# Detect MSVC compiler.
cxx_is_msvc() {
    echo "$1" | grep -qi cl.exe
}

# Parse arguments, extracting -o <output> into MSVC_OUT and the rest into
# MSVC_ARGS.  After calling, positional parameters are consumed.
msvc_parse_args() {
    MSVC_OUT=""
    MSVC_ARGS=""
    while [ $# -gt 0 ]; do
        case "$1" in
            -o) shift; MSVC_OUT="$1" ;;
            *)  MSVC_ARGS="$MSVC_ARGS $1" ;;
        esac
        shift
    done
}

# Remove JIT-only defines that don't apply to ahead-of-time compilation.
msvc_strip_jit_flags() {
    echo "$1" | sed 's|/DHILTI_JIT_DLL ||g'
}
