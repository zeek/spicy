# Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

set(AUTOGEN_H "${PROJECT_BINARY_DIR}/include/hilti/autogen")
set(AUTOGEN_CC "${PROJECT_BINARY_DIR}/hilti/src/autogen")
file(MAKE_DIRECTORY "${AUTOGEN_H}" "${AUTOGEN_CC}")
file(MAKE_DIRECTORY "${PROJECT_BINARY_DIR}/bin" "${PROJECT_BINARY_DIR}/lib")

##### Compiler library

flex_target(scanner_hilti src/compiler/parser/scanner.ll ${AUTOGEN_CC}/__scanner.cc
            DEFINES_FILE ${AUTOGEN_CC}/__scanner.h)
bison_target_pp(parser_hilti src/compiler/parser/parser.yy ${AUTOGEN_CC}/__parser.cc DEFINES_FILE
                ${AUTOGEN_CC}/__parser.h)

bison_source(src/compiler/parser/driver.cc ${AUTOGEN_CC})
bison_source(${AUTOGEN_CC}/__scanner.cc ${AUTOGEN_CC})
bison_source(${AUTOGEN_CC}/__parser.cc ${AUTOGEN_CC})

include(TypeErase)
autogen_type_erased(SOURCES_TYPE_ERASED include/hilti/ast/node.api NO)
autogen_type_erased(SOURCES_TYPE_ERASED include/hilti/ast/ctor.api YES)
autogen_type_erased(SOURCES_TYPE_ERASED include/hilti/ast/declaration.api YES)
autogen_type_erased(SOURCES_TYPE_ERASED include/hilti/ast/expression.api YES)
autogen_type_erased(SOURCES_TYPE_ERASED include/hilti/ast/expressions/resolved-operator.api YES)
autogen_type_erased(SOURCES_TYPE_ERASED include/hilti/ast/operator.api YES)
autogen_type_erased(SOURCES_TYPE_ERASED include/hilti/ast/statement.api YES)
autogen_type_erased(SOURCES_TYPE_ERASED include/hilti/ast/type.api YES)

include(ASTOperators)
autogen_operators(SOURCES_OPERATORS hilti include/hilti/ast/operators ${AUTOGEN_H}/operators.decl
                  ${AUTOGEN_CC}/operators-implementations.cc)

autogen_dispatchers(
    SOURCES_TYPE_ERASED ${AUTOGEN_H}/__dispatchers.h "hilti/ast/all.h"
    ${CMAKE_CURRENT_SOURCE_DIR}/include/hilti/ast/nodes.decl ${AUTOGEN_H}/operators.decl)

set(SOURCES
    src/ast/builder/builder.cc
    src/ast/builder/type.cc
    src/ast/declarations/imported-module.cc
    src/ast/doc-string.cc
    src/ast/expression.cc
    src/ast/expressions
    src/ast/expressions/id.cc
    src/ast/location.cc
    src/ast/meta.cc
    src/ast/module.cc
    src/ast/node.cc
    src/ast/node_ref.cc
    src/ast/scope.cc
    src/ast/scope-lookup.cc
    src/ast/type.cc
    src/ast/types/enum.cc
    src/ast/types/integer.cc
    src/ast/types/library.cc
    src/ast/types/struct.cc
    src/ast/types/tuple.cc
    src/base/code-formatter.cc
    src/base/logger.cc
    src/base/preprocessor.cc
    src/base/timing.cc
    src/base/type_erase.cc
    src/base/util.cc
    src/compiler/codegen/codegen.cc
    src/compiler/codegen/coercions.cc
    src/compiler/codegen/ctors.cc
    src/compiler/codegen/expressions.cc
    src/compiler/codegen/expressions.cc
    src/compiler/codegen/operators.cc
    src/compiler/codegen/statements.cc
    src/compiler/codegen/types.cc
    src/compiler/codegen/unpack.cc
    src/compiler/coercion.cc
    src/compiler/context.cc
    src/compiler/cxx/elements.cc
    src/compiler/cxx/formatter.cc
    src/compiler/cxx/linker.cc
    src/compiler/cxx/unit.cc
    src/compiler/driver.cc
    src/compiler/init.cc
    src/compiler/jit.cc
    src/compiler/optimizer.cc
    src/compiler/parser/driver.cc
    src/compiler/plugin.cc
    src/compiler/unit.cc
    src/compiler/visitors/coercer.cc
    src/compiler/visitors/constant-folder.cc
    src/compiler/visitors/normalizer.cc
    src/compiler/visitors/printer.cc
    src/compiler/visitors/renderer.cc
    src/compiler/visitors/resolver.cc
    src/compiler/visitors/scope-builder.cc
    src/compiler/visitors/validator.cc
    src/global.cc
    # Already included in hilti-rt, which we pull in.
    # src/3rdparty/utf8proc/utf8proc.c
    ${SOURCES_TYPE_ERASED}
    ${SOURCES_OPERATORS}
    ${AUTOGEN_CC}/config.cc
    ${BISON_parser_hilti_OUTPUTS}
    ${FLEX_scanner_hilti_OUTPUTS})

add_library(hilti-objects OBJECT ${SOURCES})
set_property(TARGET hilti-objects PROPERTY POSITION_INDEPENDENT_CODE ON)
target_compile_options(hilti-objects PRIVATE "-Wall")
target_compile_options(hilti-objects PRIVATE $<$<CONFIG:Debug>:-O0>)
target_include_directories(hilti-objects BEFORE
                           PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
target_include_directories(hilti-objects BEFORE
                           PUBLIC $<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/include>)

# Unclear why we need this: Without it, the generated Bison/Flex get a broken
# include path on some systems. (Seen on Ubuntu 19.10).
set_target_properties(hilti-objects PROPERTIES NO_SYSTEM_FROM_IMPORTED true)

target_link_libraries(hilti-objects
                      PUBLIC $<IF:$<CONFIG:Debug>,hilti-rt-debug-objects,hilti-rt-objects>)
target_link_libraries(hilti-objects PUBLIC ${CMAKE_THREAD_LIBS_INIT} ${CMAKE_DL_LIBS})

add_dependencies(hilti-objects reproc++)
target_include_directories(hilti-objects BEFORE
                           PRIVATE ${PROJECT_SOURCE_DIR}/3rdparty/reproc/reproc++/include)

add_library(hilti)
hilti_link_object_libraries_in_tree(hilti PUBLIC)

##### Configuration files

# Additional flags
if (APPLE)
    set(addl_cxx_flags "-isysroot ${CMAKE_OSX_SYSROOT}")
    set(addl_ld_flags "-isysroot ${CMAKE_OSX_SYSROOT}")
endif ()

# HILTI library directories
set_config_val(
    HILTI_CONFIG_LIBRARY_DIRS
    "!INSTALL!${CMAKE_INSTALL_FULL_DATADIR}/hilti !BUILD!${PROJECT_SOURCE_DIR}/hilti/lib")

# Include directories
set_config_val(
    HILTI_CONFIG_RUNTIME_CXX_INCLUDE_DIRS
    "!INSTALL!${CMAKE_INSTALL_FULL_INCLUDEDIR} !BUILD!${PROJECT_SOURCE_DIR}/hilti/runtime/include !BUILD!${PROJECT_BINARY_DIR}/include"
)
set_config_val(
    HILTI_CONFIG_TOOLCHAIN_CXX_INCLUDE_DIRS
    "!INSTALL!${CMAKE_INSTALL_FULL_INCLUDEDIR} !BUILD!${PROJECT_SOURCE_DIR}/hilti/toolchain/include !BUILD!${PROJECT_BINARY_DIR}/include"
)

# CXX flags
set_config_val(HILTI_CONFIG_RUNTIME_CXX_FLAGS_DEBUG
               "${addl_cxx_flags} ${EXTRA_CXX_FLAGS} ${CMAKE_CXX_FLAGS}")
set_config_val(HILTI_CONFIG_RUNTIME_CXX_FLAGS_RELEASE
               "${addl_cxx_flags} ${EXTRA_CXX_FLAGS} ${CMAKE_CXX_FLAGS}")

# Libraries
set_config_val(HILTI_CONFIG_RUNTIME_LIBRARIES_DEBUG "hilti-rt-debug")
set_config_val(HILTI_CONFIG_RUNTIME_LIBRARIES_RELEASE "hilti-rt")

# Library directories
set_config_val(HILTI_CONFIG_RUNTIME_CXX_LIBRARY_DIRS
               "!BUILD!${CMAKE_LIBRARY_OUTPUT_DIRECTORY} !INSTALL!${CMAKE_INSTALL_FULL_LIBDIR}")
set_config_val(HILTI_CONFIG_TOOLCHAIN_CXX_LIBRARY_DIRS
               "!BUILD!${CMAKE_LIBRARY_OUTPUT_DIRECTORY} !INSTALL!${CMAKE_INSTALL_FULL_LIBDIR}")

# LD flags
set_config_val(HILTI_CONFIG_RUNTIME_LD_FLAGS_DEBUG
               "${addl_ld_flags} ${EXTRA_LD_FLAGS} ${CMAKE_EXE_LINKER_FLAGS_INIT}")
set_config_val(HILTI_CONFIG_RUNTIME_LD_FLAGS_RELEASE
               "${addl_ld_flags} ${EXTRA_LD_FLAGS} ${CMAKE_EXE_LINKER_FLAGS_INIT}")

configure_file(include/config.h.in ${AUTOGEN_H}/config.h)
configure_file(src/config.cc.in ${AUTOGEN_CC}/config.cc)

##### Binaries

add_executable(hilti-config bin/hilti-config.cc)
target_compile_options(hilti-config PRIVATE "-Wall")
hilti_link_executable_in_tree(hilti-config PRIVATE)

add_executable(hiltic bin/hiltic.cc)
target_compile_options(hiltic PRIVATE "-Wall")
hilti_link_executable_in_tree(hiltic PRIVATE)

##### Installation

install(TARGETS hilti LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(TARGETS hiltic RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(TARGETS hilti-config RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

install_headers(include hilti)
install_headers(${PROJECT_BINARY_DIR}/include/hilti hilti)
install(CODE "file(REMOVE \"\$ENV\{DESTDIR\}${CMAKE_INSTALL_FULL_INCLUDEDIR}/hilti/hilti\")"
)# Get rid of symlink.

##### Tests

add_executable(hilti-toolchain-tests tests/main.cc tests/id-base.cc tests/visitor.cc tests/util.cc)
hilti_link_executable_in_tree(hilti-toolchain-tests PRIVATE)
target_link_libraries(hilti-toolchain-tests PRIVATE doctest)
target_compile_options(hilti-toolchain-tests PRIVATE "-Wall")
add_test(NAME hilti-toolchain-tests COMMAND ${PROJECT_BINARY_DIR}/bin/hilti-toolchain-tests)
