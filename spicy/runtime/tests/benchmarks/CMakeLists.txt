# Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

set(BENCH_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/parsers.spicy")
set(BENCH_MODULE Benchmark)

list(TRANSFORM BENCH_MODULE PREPEND Benchmark_ OUTPUT_VARIABLE _generated_sources)
list(TRANSFORM _generated_sources APPEND ".cc" OUTPUT_VARIABLE _generated_sources)
list(APPEND _generated_sources "Benchmark___linker__.cc")
set_source_files_properties(${_generated_sources} PROPERTIES SKIP_LINTING ON)

if (BUILD_TOOLCHAIN)
    add_custom_command(
        OUTPUT ${_generated_sources}
        COMMAND spicyc -x ${CMAKE_CURRENT_BINARY_DIR}/Benchmark "${BENCH_SOURCES}"
        DEPENDS spicyc ${BENCH_SOURCES}
        COMMENT "Generating C++ code for Benchmark")

    add_executable(spicy-rt-parsing-benchmark parsing.cc ${_generated_sources})
    target_compile_options(spicy-rt-parsing-benchmark PRIVATE -Wall -Wno-error)
    target_link_libraries(spicy-rt-parsing-benchmark
                          PRIVATE $<IF:$<CONFIG:Debug>,spicy-rt-debug,spicy-rt>)
    target_link_libraries(spicy-rt-parsing-benchmark
                          PRIVATE $<IF:$<CONFIG:Debug>,hilti-rt-debug,hilti-rt>)
    target_link_libraries(spicy-rt-parsing-benchmark PRIVATE benchmark)
endif ()
