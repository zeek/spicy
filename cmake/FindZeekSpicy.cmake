# Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.
#
# CMake helpers for Zeek plugins to build Spicy parsers.
#
# If the full Spicy toolchain is available, either set PATH to contain
# spicy-config or set SPICY_CONFIG to its location.
#
# If only the Spicy runtime is available, set SPICY_RUNTIME_DIR to its
# installation root. Spicy source files can't be recompiled then.

find_program(spicy_config spicy-config HINTS ${SPICY_ROOT_DIR}/bin ${SPICY_ROOT_DIR}/build/bin)

if ( spicy_config )
    # Full Spicy toolchain available, use it.
    execute_process(COMMAND "${spicy_config}" --spicyc
                    OUTPUT_VARIABLE spicyc
                    OUTPUT_STRIP_TRAILING_WHITESPACE)

    string(REPLACE "spicyc" "spicyz" spicyz "${spicyc}")

    execute_process(COMMAND "${spicy_config}" --include-dirs --zeek-include-dirs
                    OUTPUT_VARIABLE spicy_include_directories
                    OUTPUT_STRIP_TRAILING_WHITESPACE)

    string(REPLACE " " ";" spicy_include_directories "${spicy_include_directories}")
    list(TRANSFORM spicy_include_directories PREPEND "-I")
    string(REPLACE ";" " " spicy_include_directories "${spicy_include_directories}")

    message(STATUS "Spicy compiler       : ${spicyz}")

elseif ( NOT "${SPICY_RUNTIME_DIR}" STREQUAL "" )
    # No Spicy toolchain available, see if we have at least the runtime installed.
    if ( IS_DIRECTORY "${SPICY_RUNTIME_DIR}/runtime/include/spicy" )
        message(STATUS "No Spicy toolchain available, cannot recreate Spicy parsers")
        set(spicy_include_directories "-I${SPICY_RUNTIME_DIR}/runtime/include")
    else ()
        message(FATAL_ERROR "SPICY_RUNTIME_DIR set, but cannot find Spicy includes (runtime=${SPICY_RUNTIME_DIR})")
    endif ()

else ()
    message(FATAL_ERROR "cannot determine location of Spicy installation")
endif ()

file(MAKE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src/autogen)

# Register a Spicy source file for compilation.
function(zeek_plugin_spicy module)
    set(inputs ${ARGN})
    list(TRANSFORM inputs PREPEND "${PROJECT_SOURCE_DIR}/")

    list(APPEND _spicy_modules ${module})
    list(APPEND _spicy_inputs "${inputs}")
    set(_spicy_modules "${_spicy_modules}" PARENT_SCOPE)
    set(_spicy_inputs "${_spicy_inputs}" PARENT_SCOPE)
endfunction()

# Build all registered Spicy source files.
function(zeek_plugin_spicy_link)
    set(prefix "${CMAKE_CURRENT_SOURCE_DIR}/src/autogen")
    set(out_cc "")

    foreach ( module ${_spicy_modules} )
        list(APPEND out_cc "${prefix}/${module}.cc")
        list(APPEND out_cc "${prefix}/spicy_hooks_${module}.cc")
    endforeach ()

    list(APPEND out_cc "${prefix}/spicy_init.cc")
    list(APPEND out_cc "${prefix}/__linker__.cc")
    list(REMOVE_DUPLICATES out_cc)

    add_custom_command(OUTPUT ${out_cc}
                       COMMAND ${spicyz}
                       ARGS -c ${prefix}/ -O ${_spicy_inputs}
                       DEPENDS ${_spicy_inputs} ${spicyz}
                       COMMENT "[Spicy] Generating C++ code")
    set_source_files_properties(${out_cc} PROPERTIES GENERATED TRUE)
    set_source_files_properties(${out_cc} PROPERTIES COMPILE_FLAGS "${spicy_include_directories} -std=c++17")

    list(APPEND _plugin_objs ${out_cc})
    set(_plugin_objs "${_plugin_objs}" PARENT_SCOPE)
endfunction ()
