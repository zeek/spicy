# Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

# Declares a new fuzzer target.
function (fuzz_parser)
    set(options)
    set(oneValueArg PARSER)
    set(multiValueArgs MODULES SOURCES)

    cmake_parse_arguments(PARSE_ARGV 0 FUZZ "${options}" "${oneValueArg}" "${multiValueArgs}")

    if (NOT DEFINED FUZZ_PARSER)
        message(FATAL_ERROR "PARSER" is required)
    endif ()

    string(REPLACE "::" "_" _parser ${FUZZ_PARSER})

    list(TRANSFORM FUZZ_MODULES PREPEND ${_parser}_ OUTPUT_VARIABLE _generated_sources)
    list(TRANSFORM _generated_sources APPEND ".cc" OUTPUT_VARIABLE _generated_sources)
    list(APPEND _generated_sources "${_parser}___linker__.cc")

    add_custom_command(
        OUTPUT ${_generated_sources}
        COMMAND ${CMAKE_BINARY_DIR}/bin/spicyc -x ${CMAKE_CURRENT_BINARY_DIR}/${_parser}
                "${FUZZ_SOURCES}"
        DEPENDS spicyc
        COMMENT "Generating C++ code for ${FUZZ_PARSER}")

    add_executable(fuzz-${_parser} fuzz.cc ${_generated_sources})
    target_compile_definitions(fuzz-${_parser} PRIVATE SPICY_FUZZ_PARSER="${_parser}")
    target_compile_options(fuzz-${_parser} PRIVATE -fsanitize=fuzzer-no-link)
    target_link_options(fuzz-${_parser} PRIVATE -fsanitize=fuzzer-no-link)

    set(_libfuzzer_lib $ENV{LIBFUZZER_LIB})
    if ("${_libfuzzer_lib}" STREQUAL "")
        message(FATAL_ERROR "When building fuzzers the environment variable LIBFUZZER_LIB "
                            "must contain the path to libclang_rt.fuzzer_no_main-<arch>.a")
    endif ()
    if (NOT EXISTS ${_libfuzzer_lib})
        message(FATAL_ERROR "Configured LIBFUZZER_LIB ${_libfuzzer_lib} does not exist")
    endif ()

    target_link_libraries(fuzz-${_parser} spicy-rt hilti-rt "${_libfuzzer_lib}")
endfunction ()

fuzz_parser(PARSER "DHCP::Message" SOURCES ${CMAKE_SOURCE_DIR}/spicy-dhcp/analyzer/analyzer.spicy
            MODULES DHCP)
fuzz_parser(PARSER "TFTP::Packet" SOURCES ${CMAKE_SOURCE_DIR}/spicy-tftp/analyzer/tftp.spicy
            MODULES TFTP)
fuzz_parser(PARSER "pe::ImageFile" SOURCES ${CMAKE_SOURCE_DIR}/spicy-pe/analyzer/analyzer.spicy
            MODULES PE)
fuzz_parser(PARSER "PNG::File" SOURCES ${CMAKE_SOURCE_DIR}/spicy-png/analyzer/analyzer.spicy
            MODULES PNG)
fuzz_parser(PARSER "dns::Message" SOURCES ${CMAKE_SOURCE_DIR}/spicy-dns/analyzer/analyzer.spicy
            MODULES DNS)

foreach (P IN ITEMS Request Requests Reply Replies)
    fuzz_parser(PARSER "HTTP::${P}" SOURCES ${CMAKE_SOURCE_DIR}/spicy-http/analyzer/analyzer.spicy
                MODULES HTTP filter)
endforeach ()
