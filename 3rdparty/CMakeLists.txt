# Note that most of the subdirectories here don't need to be known
# to CMake because we directly pick out the pieces where we need
# them.

option(DOCTEST_NO_INSTALL  "Skip the installation process" ON)
add_subdirectory(doctest)

add_subdirectory(justrx)

set(FIBER_SHARED OFF)
set(FIBER_OBJECT ON)
add_subdirectory(fiber)

set(BENCHMARK_ENABLE_GTEST_TESTS OFF)
set(BENCHMARK_ENABLE_TESTING OFF)
set(BENCHMARK_ENABLE_INSTALL OFF)
add_subdirectory(benchmark)
