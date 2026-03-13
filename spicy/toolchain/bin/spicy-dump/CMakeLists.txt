# Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

add_executable(spicy-dump main.cc printer-text.cc printer-json.cc)
if (NOT MSVC)
    target_compile_options(spicy-dump PRIVATE "-Wall")
endif ()
spicy_link_executable_in_tree(spicy-dump PRIVATE)

if (MSVC)
    # Export HILTI/Spicy runtime symbols so JIT-compiled HLTO DLLs can link
    # against the host executable at load time.
    # Place the import library next to the executable so spicy-dump's JIT
    # code can find it via currentExecutable().replace_extension(".lib").
    # cmake-format: off
    set_target_properties(
        spicy-dump
        PROPERTIES
            WINDOWS_EXPORT_ALL_SYMBOLS ON
            ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}"
    )
    # cmake-format: on
endif ()

install(TARGETS spicy-dump RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
