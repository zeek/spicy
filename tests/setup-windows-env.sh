#!/usr/bin/env bash
#
# Sets up the environment for running BTest on Windows (Git Bash).
#
# Source this script before running btest:
#   source ./setup-windows-env.sh
#   btest -j 5
#   btest -d hilti.hiltic.jit.hilti-cxx
#
# Environment:
#   SPICY_BUILD_DIRECTORY  Override the auto-detected build directory.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Auto-detect build directory if not explicitly set.
if [ -z "$SPICY_BUILD_DIRECTORY" ]; then
    for candidate in \
        "$REPO_ROOT/out/build/x64-Release" \
        "$REPO_ROOT/out/build/x64-Debug" \
        "$REPO_ROOT/build"; do
        if [ -f "$candidate/CMakeCache.txt" ]; then
            SPICY_BUILD_DIRECTORY="$candidate"
            break
        fi
    done

    if [ -z "$SPICY_BUILD_DIRECTORY" ]; then
        echo "Error: Cannot auto-detect build directory." >&2
        echo "Set SPICY_BUILD_DIRECTORY or build in one of:" >&2
        echo "  $REPO_ROOT/out/build/x64-Release" >&2
        echo "  $REPO_ROOT/out/build/x64-Debug" >&2
        echo "  $REPO_ROOT/build" >&2
        return 1 2>/dev/null || exit 1
    fi
fi

if [ ! -f "$SPICY_BUILD_DIRECTORY/CMakeCache.txt" ]; then
    echo "Error: No CMakeCache.txt in $SPICY_BUILD_DIRECTORY" >&2
    echo "Is this a valid build directory?" >&2
    return 1 2>/dev/null || exit 1
fi

export MSYS=disable_pcon
export SPICY_BUILD_DIRECTORY
export HILTI_CXX_COMPILER_LAUNCHER=

echo "Environment configured for Windows BTest."
echo "  SPICY_BUILD_DIRECTORY=$SPICY_BUILD_DIRECTORY"
echo ""
echo "Now cd to the tests directory and run btest:"
echo "  cd $SCRIPT_DIR"
echo "  btest -j 5"
