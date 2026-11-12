# Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

# One file and module per benchmark. Each file is compiled in its own call: PIR falls back for a
# whole compilation, and legacy cannot compile two modules that share a bytes literal in one call.
set(BENCH_SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/unit-vector-size.spicy"
    "${CMAKE_CURRENT_SOURCE_DIR}/unit-vector-lookahead.spicy"
    "${CMAKE_CURRENT_SOURCE_DIR}/regex.spicy"
    "${CMAKE_CURRENT_SOURCE_DIR}/unit-switch.spicy"
    "${CMAKE_CURRENT_SOURCE_DIR}/unit-nested.spicy"
    "${CMAKE_CURRENT_SOURCE_DIR}/unit-bytes.spicy"
)
set(BENCH_MODULE
    Benchmark
    BenchmarkLookahead
    BenchmarkRegex
    BenchmarkSwitch
    BenchmarkNested
    BenchmarkBytes
)
set(PIR_BENCH_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/unit-vector-size.spicy")

set(_generated_sources)
set(_legacy_commands)
foreach(_source _module IN ZIP_LISTS BENCH_SOURCES BENCH_MODULE)
    get_filename_component(_name "${_source}" NAME_WE)
    string(MAKE_C_IDENTIFIER "${_name}" _name)
    list(
        APPEND _generated_sources
        Benchmark_${_name}_${_module}.cc
        Benchmark_${_name}___linker__.cc
    )
    list(
        APPEND _legacy_commands
        COMMAND
        spicyc
        -x
        ${CMAKE_CURRENT_BINARY_DIR}/Benchmark_${_name}
        "${_source}"
    )
endforeach()

set(_pir_generated_sources)
foreach(_source IN LISTS PIR_BENCH_SOURCES)
    get_filename_component(_name "${_source}" NAME_WE)
    string(MAKE_C_IDENTIFIER "${_name}" _name)
    list(
        APPEND _pir_generated_sources
        PIRBench_${_name}__r__spicy_pir_backend.cc
        PIRBench_${_name}___linker__.cc
    )
endforeach()

if(CMAKE_VERSION VERSION_GREATER_EQUAL "3.27")
    set_source_files_properties(
        ${_generated_sources}
        ${_pir_generated_sources}
        PROPERTIES SKIP_LINTING ON
    )
endif()

if(BUILD_TOOLCHAIN)
    add_custom_command(
        OUTPUT ${_generated_sources} ${_legacy_commands}
        DEPENDS spicyc ${BENCH_SOURCES}
        COMMENT "Generating C++ code for Benchmark"
    )

    add_executable(spicy-rt-parsing-benchmark EXCLUDE_FROM_ALL parsing.cc ${_generated_sources})
    if(NOT MSVC)
        target_compile_options(spicy-rt-parsing-benchmark PRIVATE -Wall -Wno-error)
    endif()
    target_link_libraries(
        spicy-rt-parsing-benchmark
        PRIVATE $<IF:$<CONFIG:Debug>,spicy-rt-debug,spicy-rt>
    )
    target_link_libraries(
        spicy-rt-parsing-benchmark
        PRIVATE $<IF:$<CONFIG:Debug>,hilti-rt-debug,hilti-rt>
    )
    target_link_libraries(spicy-rt-parsing-benchmark PRIVATE benchmark::benchmark)

    set(_pir_commands)
    foreach(_source IN LISTS PIR_BENCH_SOURCES)
        get_filename_component(_name "${_source}" NAME_WE)
        string(MAKE_C_IDENTIFIER "${_name}" _name)
        list(
            APPEND _pir_commands
            COMMAND
            ${CMAKE_COMMAND}
            -DSPICYC=$<TARGET_FILE:spicyc>
            -DSOURCE=${_source}
            -P
            ${CMAKE_CURRENT_SOURCE_DIR}/verify-pir-route.cmake
            COMMAND
            spicyc
            --experimental-pir
            --strict-public-api
            -W
            no-unused-field
            -x
            ${CMAKE_CURRENT_BINARY_DIR}/PIRBench_${_name}
            "${_source}"
        )
    endforeach()

    add_custom_command(
        OUTPUT ${_pir_generated_sources} ${_pir_commands}
        DEPENDS spicyc ${PIR_BENCH_SOURCES} ${CMAKE_CURRENT_SOURCE_DIR}/verify-pir-route.cmake
        COMMENT "Generating C++ code for the PIR benchmarks"
    )

    add_executable(
        spicy-rt-parsing-pir-benchmark
        EXCLUDE_FROM_ALL
        parsing.cc
        ${_pir_generated_sources}
    )
    if(NOT MSVC)
        target_compile_options(
            spicy-rt-parsing-pir-benchmark
            PRIVATE -Wall -Wno-error -Wno-invalid-offsetof
        )
    endif()
    target_link_libraries(
        spicy-rt-parsing-pir-benchmark
        PRIVATE $<IF:$<CONFIG:Debug>,spicy-rt-debug,spicy-rt>
    )
    target_link_libraries(
        spicy-rt-parsing-pir-benchmark
        PRIVATE $<IF:$<CONFIG:Debug>,hilti-rt-debug,hilti-rt>
    )
    target_link_libraries(spicy-rt-parsing-pir-benchmark PRIVATE benchmark::benchmark)
endif()
