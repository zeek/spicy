# Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

##### Compiler library.

set(AUTOGEN_H        "${CMAKE_BINARY_DIR}/include/spicy/autogen")
set(AUTOGEN_CC       "${CMAKE_BINARY_DIR}/spicy/src/autogen")
file(MAKE_DIRECTORY  "${AUTOGEN_H}" "${AUTOGEN_CC}")
file(MAKE_DIRECTORY  "${CMAKE_BINARY_DIR}/bin" "${CMAKE_BINARY_DIR}/lib")

set(AUTOGEN_H_HILTI  "${CMAKE_BINARY_DIR}/include/hilti/autogen")

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
                                        "spicy/ast/all.h"
                                        ${CMAKE_CURRENT_SOURCE_DIR}/../../hilti/toolchain/include/hilti/ast/nodes.decl
                                        ${CMAKE_CURRENT_SOURCE_DIR}/include/spicy/ast/nodes.decl
                                        ${AUTOGEN_H_HILTI}/operators.decl
                                        ${AUTOGEN_H}/operators.decl)

autogen_dispatchers(PRODUCTIONS_TYPE_ERASED ${AUTOGEN_H}/__dispatchers-productions.h
                                            "spicy/ast/all.h"
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
    src/compiler/driver.cc
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

add_library(spicy-objects OBJECT ${SOURCES_COMPILER})
set_property(TARGET spicy-objects PROPERTY POSITION_INDEPENDENT_CODE ON)
target_compile_options(spicy-objects PRIVATE "-Wall")
target_compile_options(spicy-objects PRIVATE $<$<CONFIG:Debug>:-O0>)
target_link_libraries(spicy-objects PUBLIC $<IF:$<CONFIG:Debug>,spicy-rt-debug-objects,spicy-rt-objects>)
target_link_hilti(spicy-objects PUBLIC)
target_link_libraries(spicy-objects  PRIVATE Threads::Threads ${CMAKE_DL_LIBS})
target_link_options(spicy-objects    PRIVATE $<$<CONFIG:Debug>:-O0>)
target_include_directories(spicy-objects BEFORE PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
target_include_directories(spicy-objects BEFORE PUBLIC $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>)

# Unclear why we need this: Without it, the generated Bison/Flex get a broken
# include path on some systems. (Seen on Ubuntu 19.10).
set_target_properties(spicy-objects PROPERTIES NO_SYSTEM_FROM_IMPORTED true)

add_library(spicy)
target_link_libraries(spicy PUBLIC spicy-objects)
target_link_hilti(spicy PUBLIC) # doesn't seem to transfer from spicy-objects
target_link_libraries(hilti PUBLIC $<IF:$<CONFIG:Debug>,spicy-rt-debug-objects,spicy-rt-objects>) # doesn't transfer from hilti-objects

##### Configuration files

# Spicy library directories
set_config_val(SPICY_CONFIG_LIBRARY_DIRS "!INSTALL!${CMAKE_INSTALL_FULL_DATADIR}/spicy !BUILD!${CMAKE_SOURCE_DIR}/spicy/lib")

# Include directories
set_config_val(SPICY_CONFIG_RUNTIME_INCLUDE_DIRS   "!INSTALL!${CMAKE_INSTALL_FULL_INCLUDEDIR} !BUILD!${CMAKE_SOURCE_DIR}/spicy/runtime/include !BUILD!${CMAKE_BINARY_DIR}/include")

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
configure_file(src/config.cc.in ${AUTOGEN_CC}/config.cc)

##### Binaries

add_executable(spicy-config bin/spicy-config.cc)
target_compile_options(spicy-config PRIVATE "-Wall")
target_link_spicy(spicy-config PRIVATE)

add_executable(spicyc bin/spicyc.cc)
target_compile_options(spicyc PRIVATE "-Wall")
target_link_spicy(spicyc PRIVATE)

add_executable(spicy-driver bin/spicy-driver.cc)
target_compile_options(spicy-driver PRIVATE "-Wall")
target_link_spicy(spicy-driver PRIVATE)

add_executable(spicy-doc bin/spicy-doc.cc)
target_compile_options(spicy-doc PRIVATE "-Wall")
target_link_spicy(spicy-doc PRIVATE)

add_subdirectory(bin/spicy-dump)

add_custom_target(spicy-build ALL)
add_custom_command(TARGET spicy-build
                   POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/bin/spicy-build
                                                               ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})

## Installation

install(TARGETS   spicy LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(TARGETS   spicyc spicy-config spicy-driver RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(PROGRAMS  ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/spicy-build        DESTINATION ${CMAKE_INSTALL_BINDIR})

install_headers(include spicy)
install_headers(${CMAKE_BINARY_DIR}/include/spicy spicy)
install(CODE "file(REMOVE ${CMAKE_INSTALL_FULL_INCLUDEDIR}/spicy/spicy)") # Get rid of symlink

## Tests

add_executable(spicy-toolchain-tests
               tests/main.cc
               tests/grammar.cc)
target_link_spicy(spicy-toolchain-tests PRIVATE)
target_link_libraries(spicy-toolchain-tests PRIVATE doctest)
target_compile_options(spicy-toolchain-tests PRIVATE "-Wall")
add_test(NAME spicy-toolchain-tests COMMAND ${CMAKE_BINARY_DIR}/bin/spicy-toolchain-tests)
