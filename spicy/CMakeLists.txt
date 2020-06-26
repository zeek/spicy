# Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

##### Compiler library.

set(AUTOGEN_H        "${CMAKE_CURRENT_BINARY_DIR}/include/spicy/autogen")
set(AUTOGEN_RT_H     "${CMAKE_CURRENT_BINARY_DIR}/include/spicy/rt/autogen")
set(AUTOGEN_CC       "${CMAKE_CURRENT_BINARY_DIR}/src/autogen")
file(MAKE_DIRECTORY  "${AUTOGEN_H}" "${AUTOGEN_RT_H}" "${AUTOGEN_CC}")
file(MAKE_DIRECTORY  "${CMAKE_CURRENT_BINARY_DIR}/bin" "${CMAKE_CURRENT_BINARY_DIR}/lib")

set(AUTOGEN_H_HILTI  "${CMAKE_CURRENT_BINARY_DIR}/../hilti/include/hilti/autogen")

FLEX_TARGET(scanner_spicy src/compiler/parser/scanner.ll ${AUTOGEN_CC}/__scanner.cc
            DEFINES_FILE ${AUTOGEN_CC}/__scanner.h)
BISON_TARGET(parser_spicy src/compiler/parser/parser.yy ${AUTOGEN_CC}/__parser.cc
            DEFINES_FILE ${AUTOGEN_CC}/__parser.h
)

bison_source(src/compiler/parser/driver.cc ${AUTOGEN_CC})
bison_source(${AUTOGEN_CC}/__scanner.cc ${AUTOGEN_CC})
bison_source(${AUTOGEN_CC}/__parser.cc ${AUTOGEN_CC})

include(TypeErase)
autogen_type_erased(SOURCES_TYPE_ERASED include/spicy/ast/types/unit-item.api YES)
autogen_type_erased(SOURCES_TYPE_ERASED include/spicy/compiler/detail/codegen/production.api NO)

include(ASTOperators)
autogen_operators(SOURCES_OPERATORS
                  spicy
                  include/spicy/ast/operators
                  ${AUTOGEN_H}/operators.decl
                  ${AUTOGEN_CC}/operators-implementations.cc
)

autogen_dispatchers(SOURCES_TYPE_ERASED ${AUTOGEN_H}/__dispatchers.h
                                        ${CMAKE_CURRENT_SOURCE_DIR}/../hilti/include/hilti/ast/nodes.decl
                                        ${CMAKE_CURRENT_SOURCE_DIR}/include/spicy/ast/nodes.decl
                                        ${AUTOGEN_H_HILTI}/operators.decl
                                        ${AUTOGEN_H}/operators.decl)

autogen_dispatchers(PRODUCTIONS_TYPE_ERASED ${AUTOGEN_H}/__dispatchers-productions.h
                                            ${CMAKE_CURRENT_SOURCE_DIR}/include/compiler/detail/codegen/productions.decl)

set(SOURCES_COMPILER
    src/ast/types/bitfield.cc
    src/ast/types/unit.cc
    src/ast/types/unit-items/field.cc
    src/ast/types/unit-items/switch.cc
    src/compiler/codegen/codegen.cc
    src/compiler/codegen/grammar.cc
    src/compiler/codegen/grammar-builder.cc
    src/compiler/codegen/parser-builder.cc
    src/compiler/codegen/parsers/literals.cc
    src/compiler/codegen/parsers/types.cc
    src/compiler/codegen/production.cc
    src/compiler/codegen/productions/look-ahead.cc
    src/compiler/codegen/productions/switch.cc
    src/compiler/codegen/unit-builder.cc
    src/compiler/parser/driver.cc
    src/compiler/plugin.cc
    src/compiler/visitors/apply-coercions.cc
    src/compiler/visitors/coercer.cc
    src/compiler/visitors/id-resolver.cc
    src/compiler/visitors/printer.cc
    src/compiler/visitors/scope-builder.cc
    src/compiler/visitors/validator.cc

    ${SOURCES_TYPE_ERASED}
    ${SOURCES_OPERATORS}
    ${PRODUCTIONS_TYPE_ERASED}

    ${AUTOGEN_CC}/config.cc
    ${BISON_parser_spicy_OUTPUTS}
    ${FLEX_scanner_spicy_OUTPUTS}
    )

add_library(spicy ${SOURCES_COMPILER})
target_compile_options(spicy PRIVATE "-Wall")
target_link_libraries(spicy  PRIVATE $<IF:$<CONFIG:Debug>,spicy-rt-debug-objects,spicy-rt-objects>)
target_link_libraries(spicy  PUBLIC hilti)
target_link_libraries(spicy  PRIVATE std::filesystem)
target_include_directories(spicy BEFORE PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
target_include_directories(spicy BEFORE PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>)

# Unclear why we need this: Without it, the generated Bison/Flex get a broken
# include path on some systems. (Seen on Ubuntu 19.10).
set_target_properties(spicy PROPERTIES NO_SYSTEM_FROM_IMPORTED true)

##### Runtime library.

set(SOURCES_RUNTIME
    src/rt/base64.cc
    src/rt/driver.cc
    src/rt/global-state.cc
    src/rt/init.cc
    src/rt/parser.cc
    src/rt/sink.cc
    src/rt/util.cc
    src/rt/zlib.cc

    src/3rdparty/libb64/src/cdecode.c
    src/3rdparty/libb64/src/cencode.c
)

foreach ( lib spicy-rt spicy-rt-debug )
    add_library(${lib}-objects OBJECT ${SOURCES_RUNTIME})
    target_compile_options(${lib}-objects PRIVATE "-fPIC")
    target_link_libraries(${lib}-objects PRIVATE std::filesystem)
    target_link_libraries(${lib}-objects PUBLIC ZLIB::ZLIB)
    target_include_directories(${lib}-objects BEFORE PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
    target_include_directories(${lib}-objects BEFORE PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>)
    target_include_directories(${lib}-objects BEFORE PRIVATE include/3rdparty/libtask)

    add_library(${lib} STATIC)
    target_link_libraries(${lib} ${lib}-objects)
endforeach ()

# Build spicy-rt with release flags.
string(REPLACE " " ";" cxx_flags_release ${CMAKE_CXX_FLAGS_RELEASE})
target_compile_options(spicy-rt-debug-objects     PRIVATE ${cxx_flags_release})
target_compile_options(spicy-rt-objects           PRIVATE "-DNDEBUG;-O3;-g0;-Wall")
target_compile_definitions(spicy-rt-objects       PRIVATE "HILTI_RT_BUILD_TYPE_RELEASE")
target_link_libraries(spicy-rt-objects            PUBLIC hilti-rt-objects)

# Build spicy-rt-debug with debug flags.
string(REPLACE " " ";" cxx_flags_debug ${CMAKE_CXX_FLAGS_DEBUG})
target_compile_options(spicy-rt-debug-objects     PRIVATE ${cxx_flags_debug})
target_compile_options(spicy-rt-debug-objects     PRIVATE "-UNDEBUG;-O0;-Wall")
target_compile_definitions(spicy-rt-debug-objects PRIVATE "HILTI_RT_BUILD_TYPE_DEBUG")
target_link_libraries(spicy-rt-debug-objects      PUBLIC hilti-rt-debug-objects)

##### Configuration files

# Spicy library directories
set_config_val(SPICY_CONFIG_LIBRARY_DIRS "!INSTALL!${CMAKE_INSTALL_FULL_DATADIR}/spicy !BUILD!${CMAKE_CURRENT_SOURCE_DIR}/lib")

# Include directories

set_config_val(SPICY_CONFIG_RUNTIME_INCLUDE_DIRS_DEBUG   "!INSTALL!${CMAKE_INSTALL_FULL_INCLUDEDIR} !BUILD!${CMAKE_CURRENT_SOURCE_DIR}/include !BUILD!${CMAKE_CURRENT_BINARY_DIR}/include")
set_config_val(SPICY_CONFIG_RUNTIME_INCLUDE_DIRS_RELEASE "!INSTALL!${CMAKE_INSTALL_FULL_INCLUDEDIR} !BUILD!${CMAKE_CURRENT_SOURCE_DIR}/include !BUILD!${CMAKE_CURRENT_BINARY_DIR}/include")

# CXX flags

set_config_val(SPICY_CONFIG_RUNTIME_CXX_FLAGS_DEBUG   "")
set_config_val(SPICY_CONFIG_RUNTIME_CXX_FLAGS_RELEASE "")

# Libraries

set_config_val(SPICY_CONFIG_RUNTIME_LIBRARIES_DEBUG   "spicy-rt-debug z")
set_config_val(SPICY_CONFIG_RUNTIME_LIBRARIES_RELEASE "spicy-rt z")

# Library directories

set_config_val(SPICY_CONFIG_RUNTIME_LIBRARY_DIRS_DEBUG   "")
set_config_val(SPICY_CONFIG_RUNTIME_LIBRARY_DIRS_RELEASE "")

# LD flags

set_config_val(SPICY_CONFIG_RUNTIME_LD_FLAGS_DEBUG   "")
set_config_val(SPICY_CONFIG_RUNTIME_LD_FLAGS_RELEASE "")

# Generate configurarion

configure_file(include/config.h.in ${AUTOGEN_H}/config.h)
configure_file(include/rt/config.h.in ${AUTOGEN_RT_H}/config.h)
configure_file(src/config.cc.in ${AUTOGEN_CC}/config.cc)

##### Binaries

add_executable(spicyc bin/spicyc.cc)
target_compile_options(spicyc PRIVATE "-Wall")
target_link_libraries(spicyc PRIVATE spicy)

add_executable(spicy-config bin/spicy-config.cc)
target_compile_options(spicy-config PRIVATE "-Wall")
target_link_libraries(spicy-config PRIVATE spicy)

add_executable(spicy-driver bin/spicy-driver.cc)
target_compile_options(spicy-driver PRIVATE "-Wall")
target_link_libraries(spicy-driver PRIVATE spicy)

add_executable(spicy-doc bin/spicy-doc.cc)
target_compile_options(spicy-doc PRIVATE "-Wall")
target_link_libraries(spicy-doc PRIVATE spicy)

add_custom_target(spicy-build ALL)
add_custom_command(TARGET spicy-build
                   POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/bin/spicy-build
                                                               ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})

if ( HILTI_USE_JIT )
    add_executable(spicy-driver bin/spicy-driver.cc)
    target_link_libraries(spicy-driver PRIVATE spicy)
endif ()

set(SPICY_EXEUTABLES "spicyc" "spicy-config" "spicy-driver" "spicy-doc")

# The Compiler would not include static variable located at plugin.cc in executable
# if we do not tell the compiler. We can't choose which symbol to inlcude so we have to
# include them all.

if ( (NOT DEFINED BUILD_SHARED_LIBS) OR (NOT BUILD_SHARED_LIBS) )
    if (${CMAKE_CXX_COMPILER_ID} MATCHES "Clang")
        foreach (EXE ${SPICY_EXEUTABLES})
            target_link_options(${EXE} PRIVATE "-all_load")
        endforeach ()
    elseif (${CMAKE_CXX_COMPILER_ID} MATCHES "GNU")
        foreach (EXE ${SPICY_EXEUTABLES})
            target_link_options(${EXE} PRIVATE "--whole-archive")
        endforeach ()
    endif ()
endif ()

## Tests
add_executable(spicy-tests
               tests/main.cc
               tests/grammar.cc)
target_link_libraries(spicy-tests PRIVATE spicy doctest)
target_compile_options(spicy-tests PRIVATE "-Wall")
add_test(NAME spicy-tests COMMAND ${CMAKE_BINARY_DIR}/bin/spicy-tests)

## Installation

install(TARGETS   spicy LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(TARGETS   spicy-rt spicy-rt-debug ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(TARGETS   spicyc spicy-config spicy-driver RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(PROGRAMS  ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/spicy-build        DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES     ${CMAKE_CURRENT_SOURCE_DIR}/lib/spicy-driver-host.cc DESTINATION ${CMAKE_INSTALL_DATADIR}/spicy)
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/lib/                     DESTINATION ${CMAKE_INSTALL_DATADIR}/spicy MESSAGE_NEVER)

install_headers(include spicy)
install_headers(${CMAKE_CURRENT_BINARY_DIR}/include/spicy spicy)
install(CODE "file(REMOVE ${CMAKE_INSTALL_FULL_INCLUDEDIR}/spicy/spicy)") # Get rid of symlink
