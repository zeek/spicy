# If we run clang-tidy as part of CMake we never want to check files in this
# directory. We specify this in addition to the local `.clang-tidy` in this
# directory since it is only valid in subdirectories which do not provided
# their on `.clang-tidy` config.
set(CMAKE_C_CLANG_TIDY "")
set(CMAKE_CXX_CLANG_TIDY "")

# Do not build any code here with `-Werror`.
string(REPLACE "${werror_flags}" "" flags "${CMAKE_C_FLAGS}")
set(CMAKE_C_FLAGS "${flags}")
string(REPLACE "${werror_flags}" "" flags "${CMAKE_CXX_FLAGS}")
set(CMAKE_CXX_FLAGS "${flags}")

# Note that most of the subdirectories here don't need to be known
# to CMake because we directly pick out the pieces where we need
# them.

option(DOCTEST_NO_INSTALL "Skip the installation process" ON)
add_subdirectory(doctest)

option(JUSTRX_HAVE_BENCHMARK "Benchmark is provided" ON)
add_subdirectory(justrx)

# Use the configured C compiler as ASM compiler as well. This prevents that we
# e.g., use a Clang as C compiler, but e.g., GCC as assembler which leads to
# incompatible flags like `-Weverything` being passed to GCC from e.g.,
# `3rdparty/fiber`.
set(CMAKE_ASM_COMPILER ${CMAKE_C_COMPILER})

# The GNU toolchain by default assumes that any assembly files (of which the
# fiber library contains at least one) need an executable stack; explictly
# disable that since we do not need executable stacks and some package linters
# call this out as needlessly insecure.
set(CMAKE_ASM_FLAGS ${CMAKE_ASM_FLAGS} -Wa,--noexecstack)

set(FIBER_SHARED OFF)
set(FIBER_OBJECT ON)
add_subdirectory(fiber)

set(BENCHMARK_ENABLE_GTEST_TESTS OFF)
set(BENCHMARK_ENABLE_TESTING OFF)
set(BENCHMARK_ENABLE_INSTALL OFF)
set(BENCHMARK_ENABLE_WERROR OFF)
add_subdirectory(benchmark)

set(REPROC++ ON)
set(REPROC_MULTITHREADED OFF)
set(REPROC_OBJECT_LIBRARIES ON)
add_subdirectory(reproc)
set_property(TARGET reproc PROPERTY POSITION_INDEPENDENT_CODE ON)
set_property(TARGET reproc++ PROPERTY POSITION_INDEPENDENT_CODE ON)

# GCC-13 warns about code in reproc++. This is fixed upstream with
# DaanDeMeyer/reproc@0b23d88894ccedde04537fa23ea55cb2f8365342, but that patch
# has not landed in a release yet. Disable the warning if the compiler knows
# about it.
#
# TODO(bbannier): Drop this once reproc puts out a release officially supporting gcc-13.
include(CheckCXXCompilerFlag)
check_cxx_compiler_flag("-Wno-changes-meaning" _has_no_changes_meaning_flag)
if (_has_no_changes_meaning_flag)
    set_property(TARGET reproc++ PROPERTY COMPILE_OPTIONS "-Wno-changes-meaning")
endif ()
