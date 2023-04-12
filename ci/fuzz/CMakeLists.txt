# Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

# Declares a new fuzzer target.
function (fuzz_parser Name SpicyInput Parser)
    string(REPLACE ":" "_" parser ${Parser})
    set(name ${Name}-${parser})
    add_custom_command(
        OUTPUT "${name}.cc"
        COMMAND ${CMAKE_BINARY_DIR}/bin/spicyc -c -o "${name}.cc" "${SpicyInput}"
        DEPENDS spicyc
        COMMENT "Generating C++ code for ${Parser}")

    add_custom_command(
        OUTPUT "${name}_link.cc"
        COMMAND ${CMAKE_BINARY_DIR}/bin/spicyc -l -o "${name}_link.cc" "${SpicyInput}"
        DEPENDS spicyc
        COMMENT "Generating C++ linker code for ${Parser}")

    add_executable(fuzz-${name} fuzz.cc "${name}.cc" "${name}_link.cc")
    target_compile_definitions(fuzz-${name} PRIVATE SPICY_FUZZ_PARSER="${Parser}")
    target_compile_options(fuzz-${name} PRIVATE -fsanitize=fuzzer-no-link)
    target_link_options(fuzz-${name} PRIVATE -fsanitize=fuzzer-no-link)

    set(LIBFUZZER_LIB $ENV{LIBFUZZER_LIB})
    if ("${LIBFUZZER_LIB}" STREQUAL "")
        message(FATAL_ERROR "When building fuzzers the environment variable LIBFUZZER_LIB "
                            "must contain the path to libclang_rt.fuzzer_no_main-<arch>.a")
    endif ()
    if (NOT EXISTS ${LIBFUZZER_LIB})
        message(FATAL_ERROR "Configured LIBFUZZER_LIB ${LIBFUZZER_LIB} does not exist")
    endif ()

    target_link_libraries(fuzz-${name} spicy-rt hilti-rt "${LIBFUZZER_LIB}")
endfunction ()

fuzz_parser(dhcp ${CMAKE_SOURCE_DIR}/spicy-dhcp/analyzer/analyzer.spicy "dhcp::Message")
fuzz_parser(tftp ${CMAKE_SOURCE_DIR}/spicy-tftp/analyzer/tftp.spicy "TFTP::Packet")
fuzz_parser(pe ${CMAKE_SOURCE_DIR}/spicy-pe/analyzer/analyzer.spicy "pe::ImageFile")
fuzz_parser(png ${CMAKE_SOURCE_DIR}/spicy-png/analyzer/analyzer.spicy "PNG::File")
fuzz_parser(dns ${CMAKE_SOURCE_DIR}/spicy-dns/analyzer/analyzer.spicy "dns::Message")
fuzz_parser(http ${CMAKE_SOURCE_DIR}/spicy-http/analyzer/analyzer.spicy "HTTP::Request")
fuzz_parser(http ${CMAKE_SOURCE_DIR}/spicy-http/analyzer/analyzer.spicy "HTTP::Requests")
fuzz_parser(http ${CMAKE_SOURCE_DIR}/spicy-http/analyzer/analyzer.spicy "HTTP::Reply")
fuzz_parser(http ${CMAKE_SOURCE_DIR}/spicy-http/analyzer/analyzer.spicy "HTTP::Replies")
