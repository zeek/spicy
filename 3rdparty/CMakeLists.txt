# Note that most of the subdirectories here don't need to be known
# to CMake because we directly pick out the pieces where we need
# them.

option(DOCTEST_NO_INSTALL "Skip the installation process" ON)
add_subdirectory(doctest)

add_subdirectory(justrx)

# The GNU toolchain by default assumes that any assembly files (of which the
# fiber library contains at least one) need an executable stack; explictly
# disable that since we do not need executable stacks and some package linters
# call this out as needlessly insecure.
set(CMAKE_ASM_FLAGS ${CMAKE_ASM_FLAGS} -Wa,--noexecstack)
set(FIBER_SHARED OFF)
set(FIBER_OBJECT ON)
add_subdirectory(fiber)

if (${USE_BENCHMARK})
    set(BENCHMARK_ENABLE_GTEST_TESTS OFF)
    set(BENCHMARK_ENABLE_TESTING OFF)
    set(BENCHMARK_ENABLE_INSTALL OFF)
    add_subdirectory(benchmark)
endif ()

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
