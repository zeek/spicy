include(FetchContent)

# If we run clang-tidy as part of CMake we never want to check files in this
# directory. We specify this in addition to the local `.clang-tidy` in this
# directory since it is only valid in subdirectories which do not provided
# their on `.clang-tidy` config.
set(CMAKE_C_CLANG_TIDY "")
set(CMAKE_CXX_CLANG_TIDY "")

FetchContent_Declare(
    doctest
    URL "${CMAKE_CURRENT_SOURCE_DIR}/doctest"
)
# option(DOCTEST_NO_INSTALL "Skip the installation process" ON)
FetchContent_MakeAvailable(doctest)

FetchContent_Declare(
    justrx
    URL "${CMAKE_CURRENT_SOURCE_DIR}/justrx"
)
set(JUSTRX_DISABLE_TESTS ON)
# If we'd enable tests above we would need to pick up the benchmarking
# library here to avoid declaring the target twice.
set(JUSTRX_HAVE_BENCHMARK ON)
FetchContent_MakeAvailable(justrx)

FetchContent_Declare(
    fiber
    URL "${CMAKE_CURRENT_SOURCE_DIR}/fiber"
)
set(FIBER_SHARED OFF)
set(FIBER_OBJECT ON)
FetchContent_MakeAvailable(fiber)

if (CODSPEED_MODE)
    # We use codspeed.io for benchmarking in CI. Pull in
    # their patched google-benchmark if we are running there.
    set(BENCHMARK_DOWNLOAD_DEPENDENCIES ON)
    FetchContent_Declare(
        google_benchmark
        GIT_REPOSITORY https://github.com/CodSpeedHQ/codspeed-cpp
        SOURCE_SUBDIR google_benchmark
        GIT_TAG 308c87992a7bbeb8bc1c7b14981d0f63947a2dd8
    )
else()
    FetchContent_Declare(
        google_benchmark
        URL "${CMAKE_CURRENT_SOURCE_DIR}/benchmark"
    )
endif()
set(BENCHMARK_ENABLE_GTEST_TESTS OFF)
set(BENCHMARK_ENABLE_TESTING OFF)
set(BENCHMARK_ENABLE_INSTALL OFF)
set(BENCHMARK_ENABLE_WERROR OFF)
FetchContent_MakeAvailable(google_benchmark)

FetchContent_Declare(
    reproc
    URL "${CMAKE_CURRENT_SOURCE_DIR}/reproc"
)
set(REPROC++ ON)
set(REPROC_MULTITHREADED OFF)
set(REPROC_OBJECT_LIBRARIES ON)
FetchContent_MakeAvailable(reproc)
