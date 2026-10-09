# Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

set(BENCH_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/unit-vector-size.spicy"
                  "${CMAKE_CURRENT_SOURCE_DIR}/parsers.spicy")
set(BENCH_MODULE Benchmark BenchmarkOther)

list(TRANSFORM BENCH_MODULE PREPEND Benchmark_ OUTPUT_VARIABLE _generated_sources)
list(TRANSFORM _generated_sources APPEND ".cc" OUTPUT_VARIABLE _generated_sources)
list(APPEND _generated_sources "Benchmark___linker__.cc")

if (CMAKE_VERSION VERSION_GREATER_EQUAL "3.27")
    set_source_files_properties(${_generated_sources} PROPERTIES SKIP_LINTING ON)
endif ()

if (BUILD_TOOLCHAIN)
    add_custom_command(
        OUTPUT ${_generated_sources}
        COMMAND spicyc -x ${CMAKE_CURRENT_BINARY_DIR}/Benchmark ${BENCH_SOURCES}
        DEPENDS spicyc ${BENCH_SOURCES}
        COMMENT "Generating C++ code for Benchmark")

    add_executable(spicy-rt-parsing-benchmark EXCLUDE_FROM_ALL parsing.cc ${_generated_sources})
    if (NOT MSVC)
        target_compile_options(spicy-rt-parsing-benchmark PRIVATE -Wall -Wno-error)
    endif ()
    target_link_libraries(spicy-rt-parsing-benchmark
                          PRIVATE $<IF:$<CONFIG:Debug>,spicy-rt-debug,spicy-rt>)
    target_link_libraries(spicy-rt-parsing-benchmark
                          PRIVATE $<IF:$<CONFIG:Debug>,hilti-rt-debug,hilti-rt>)
    target_link_libraries(spicy-rt-parsing-benchmark PRIVATE benchmark)

    set(PIR_BENCH_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/unit-vector-size.spicy")
    set(PIR_BENCH_OUTPUTS PIRBenchmark__r__spicy_pir_backend.cc PIRBenchmark___linker__.cc
                          PIRBenchmark.h)
    add_custom_command(
        OUTPUT ${PIR_BENCH_OUTPUTS}
        COMMAND ${CMAKE_COMMAND} -DSPICYC=$<TARGET_FILE:spicyc> -DSOURCE=${PIR_BENCH_SOURCE} -P
                ${CMAKE_CURRENT_SOURCE_DIR}/verify-pir-route.cmake
        COMMAND spicyc --experimental-pir --strict-public-api -x
                ${CMAKE_CURRENT_BINARY_DIR}/PIRBenchmark "${PIR_BENCH_SOURCE}"
        COMMAND spicyc --experimental-pir --strict-public-api -P PIRBenchmark -o
                ${CMAKE_CURRENT_BINARY_DIR}/PIRBenchmark.h "${PIR_BENCH_SOURCE}"
        DEPENDS spicyc ${PIR_BENCH_SOURCE} ${CMAKE_CURRENT_SOURCE_DIR}/verify-pir-route.cmake
        COMMENT "Generating C++ for the PIR bounded-vector benchmark")
    add_executable(spicy-rt-parsing-pir-benchmark EXCLUDE_FROM_ALL parsing-pir.cc
                                                                   ${PIR_BENCH_OUTPUTS})
    target_include_directories(spicy-rt-parsing-pir-benchmark PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
    if (NOT MSVC)
        target_compile_options(spicy-rt-parsing-pir-benchmark PRIVATE -Wno-invalid-offsetof)
    endif ()
    target_link_libraries(spicy-rt-parsing-pir-benchmark
                          PRIVATE $<IF:$<CONFIG:Debug>,spicy-rt-debug,spicy-rt>)
    target_link_libraries(spicy-rt-parsing-pir-benchmark
                          PRIVATE $<IF:$<CONFIG:Debug>,hilti-rt-debug,hilti-rt>)
    target_link_libraries(spicy-rt-parsing-pir-benchmark PRIVATE benchmark)
endif ()
