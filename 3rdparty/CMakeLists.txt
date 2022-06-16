# Note that most of the subdirectories here don't need to be known
# to CMake because we directly pick out the pieces where we need
# them.

option(DOCTEST_NO_INSTALL  "Skip the installation process" ON)
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
