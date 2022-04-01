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
    target_compile_definitions(fuzz-${name} PRIVATE SPICY_FUZZ_PARSER="${Parser}"
                                                    HILTI_HAVE_SANITIZER)
    target_compile_options(fuzz-${name} PRIVATE -fsanitize=fuzzer-no-link)
    target_link_options(fuzz-${name} PRIVATE -fsanitize=fuzzer-no-link)
    target_link_libraries(
        fuzz-${name} spicy-rt hilti-rt
        "/usr/local/lib/clang/14.0.0/lib/linux/libclang_rt.fuzzer_no_main-x86_64.a")
endfunction ()

fuzz_parser(dhcp ${CMAKE_SOURCE_DIR}/spicy-dhcp/analyzer/analyzer.spicy "dhcp::Message")
fuzz_parser(tftp ${CMAKE_SOURCE_DIR}/spicy-tftp/analyzer/analyzer.spicy "tftp::Packet")
fuzz_parser(pe ${CMAKE_SOURCE_DIR}/spicy-pe/analyzer/analyzer.spicy "pe::ImageFile")
fuzz_parser(png ${CMAKE_SOURCE_DIR}/spicy-png/analyzer/analyzer.spicy "PNG::File")
fuzz_parser(dns ${CMAKE_SOURCE_DIR}/spicy-dns/analyzer/analyzer.spicy "dns::Message")
fuzz_parser(http ${CMAKE_SOURCE_DIR}/spicy-http/analyzer/analyzer.spicy "HTTP::Request")
fuzz_parser(http ${CMAKE_SOURCE_DIR}/spicy-http/analyzer/analyzer.spicy "HTTP::Requests")
fuzz_parser(http ${CMAKE_SOURCE_DIR}/spicy-http/analyzer/analyzer.spicy "HTTP::Reply")
fuzz_parser(http ${CMAKE_SOURCE_DIR}/spicy-http/analyzer/analyzer.spicy "HTTP::Replies")