# Note that most of the subdirectories here don't need to be known
# to CMake because we directly pick out the pieces where we need
# them.

option(DOCTEST_NO_INSTALL  "Skip the installation process" ON)
add_subdirectory(doctest)

add_subdirectory(justrx)

# CMake setup for libaco.
add_library(aco OBJECT libaco/acosw.S libaco/aco.c)
set_target_properties(aco PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(aco PUBLIC libaco)

set(BENCHMARK_ENABLE_GTEST_TESTS OFF)
set(BENCHMARK_ENABLE_TESTING OFF)
add_subdirectory(benchmark)
