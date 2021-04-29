#!/bin/sh

set -eu

/work/configure --enable-debug --enable-fuzzing --enable-sanitizer="${SANITIZER}" --generator=Ninja --with-clang-fuzzer-no-main=/usr/lib/llvm-12/lib/clang/12.0.1/lib/linux/libclang_rt.fuzzer_no_main-x86_64.a
ninja -C build ci/fuzz/all
cp build/bin/fuzz-* "${OUT}"
