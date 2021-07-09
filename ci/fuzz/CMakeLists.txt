function(fuzz_parser SpicyInput)
    get_filename_component(name ${SpicyInput} NAME_WLE)

    add_custom_command(
        OUTPUT "${name}.cc"
        COMMAND ${PROJECT_BINARY_DIR}/bin/spicyc -c -o "${name}.cc" "${SpicyInput}"
        DEPENDS spicyc
        )

    add_custom_command(
        OUTPUT "${name}_link.cc"
        COMMAND ${PROJECT_BINARY_DIR}/bin/spicyc -l -o "${name}_link.cc" "${SpicyInput}"
        DEPENDS spicyc
        )

    add_executable(fuzz-${name} fuzz.cc "${name}.cc" "${name}_link.cc")
    target_compile_options(fuzz-${name} PRIVATE -fsanitize=fuzzer-no-link)
    target_link_options(fuzz-${name} PRIVATE -fsanitize=fuzzer-no-link)
    if ( EXISTS "${CLANG_FUZZER_NO_MAIN}" )
        target_link_libraries(fuzz-${name} spicy-rt hilti-rt "${CLANG_FUZZER_NO_MAIN}")
    else ()
        target_link_libraries(fuzz-${name} spicy-rt hilti-rt)
    endif()
endfunction()

if (USE_FUZZING)
    fuzz_parser(${PROJECT_SOURCE_DIR}/zeek/spicy-analyzers/analyzer/protocol/dhcp/dhcp.spicy)
    fuzz_parser(${PROJECT_SOURCE_DIR}/zeek/spicy-analyzers/analyzer/protocol/ipsec/ipsec.spicy)
    fuzz_parser(${PROJECT_SOURCE_DIR}/zeek/spicy-analyzers/analyzer/protocol/openvpn/openvpn.spicy)
    fuzz_parser(${PROJECT_SOURCE_DIR}/zeek/spicy-analyzers/analyzer/protocol/wireguard/wireguard.spicy)
    fuzz_parser(${PROJECT_SOURCE_DIR}/zeek/spicy-analyzers/analyzer/protocol/tftp/tftp.spicy)
    fuzz_parser(${PROJECT_SOURCE_DIR}/zeek/spicy-analyzers/analyzer/file/pe/pe.spicy)
    fuzz_parser(${PROJECT_SOURCE_DIR}/zeek/spicy-analyzers/analyzer/file/png/PNG.spicy)
    fuzz_parser(${PROJECT_SOURCE_DIR}/zeek/spicy-analyzers/analyzer/protocol/dns/dns.spicy)
    fuzz_parser(${PROJECT_SOURCE_DIR}/zeek/spicy-analyzers/analyzer/protocol/http/http.spicy)
endif()
