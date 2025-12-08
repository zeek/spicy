# Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

set(AUTOGEN_H "${PROJECT_BINARY_DIR}/include/hilti/autogen")
set(AUTOGEN_CC "${PROJECT_BINARY_DIR}/hilti/src/autogen")
file(MAKE_DIRECTORY "${AUTOGEN_H}" "${AUTOGEN_CC}")
file(MAKE_DIRECTORY "${PROJECT_BINARY_DIR}/bin" "${PROJECT_BINARY_DIR}/lib")

##### Compiler library

flex_target(scanner_hilti src/compiler/parser/scanner.ll ${AUTOGEN_CC}/__scanner.cc
            DEFINES_FILE ${AUTOGEN_CC}/__scanner.h)
bison_target_pp(parser_hilti src/compiler/parser/parser.yy ${AUTOGEN_CC}/__parser.cc DEFINES_FILE
                ${AUTOGEN_CC}/__parser.h)

if (CMAKE_VERSION VERSION_GREATER_EQUAL "3.27")
    set_source_files_properties(${FLEX_scanner_hilti_OUTPUTS} PROPERTIES SKIP_LINTING ON)
    set_source_files_properties(${BISON_parser_hilti_OUTPUTS} PROPERTIES SKIP_LINTING ON)
endif ()

flex_bison_source(src/compiler/plugin.cc ${AUTOGEN_CC})
flex_bison_source(src/compiler/parser/driver.cc ${AUTOGEN_CC})
flex_bison_source(${AUTOGEN_CC}/__scanner.cc ${AUTOGEN_CC})
flex_bison_source(${AUTOGEN_CC}/__parser.cc ${AUTOGEN_CC})

set(SOURCES
    src/ast/ast-context.cc
    src/ast/attribute.cc
    src/ast/builder/builder.cc
    src/ast/declarations/module.cc
    src/ast/declarations/function.cc
    src/ast/declarations/field.cc
    src/ast/doc-string.cc
    src/ast/visitor.cc
    src/ast/ctor.cc
    src/ast/ctors/bitfield.cc
    src/ast/ctors/map.cc
    src/ast/ctors/struct.cc
    src/ast/declaration.cc
    src/ast/expression.cc
    src/ast/function.cc
    src/ast/expressions/name.cc
    src/ast/location.cc
    src/ast/meta.cc
    src/ast/node.cc
    src/ast/operator.cc
    src/ast/operator-registry.cc
    src/ast/operators/address.cc
    src/ast/operators/bitfield.cc
    src/ast/operators/bool.cc
    src/ast/operators/bytes.cc
    src/ast/operators/enum.cc
    src/ast/operators/error.cc
    src/ast/operators/exception.cc
    src/ast/operators/function.cc
    src/ast/operators/generic.cc
    src/ast/operators/interval.cc
    src/ast/operators/list.cc
    src/ast/operators/map.cc
    src/ast/operators/network.cc
    src/ast/operators/optional.cc
    src/ast/operators/port.cc
    src/ast/operators/real.cc
    src/ast/operators/reference.cc
    src/ast/operators/regexp.cc
    src/ast/operators/result.cc
    src/ast/operators/set.cc
    src/ast/operators/signed-integer.cc
    src/ast/operators/stream.cc
    src/ast/operators/string.cc
    src/ast/operators/struct.cc
    src/ast/operators/time.cc
    src/ast/operators/tuple.cc
    src/ast/operators/union.cc
    src/ast/operators/unsigned-integer.cc
    src/ast/operators/vector.cc
    src/ast/statement.cc
    src/ast/type.cc
    src/ast/scope.cc
    src/ast/scope-lookup.cc
    src/ast/statements/switch.cc
    src/ast/statements/try.cc
    src/ast/types/bitfield.cc
    src/ast/types/enum.cc
    src/ast/types/function.cc
    src/ast/types/integer.cc
    src/ast/types/name.cc
    src/ast/types/operand-list.cc
    src/ast/types/struct.cc
    src/ast/types/tuple.cc
    src/ast/types/union.cc
    src/base/code-formatter.cc
    src/base/logger.cc
    src/base/preprocessor.cc
    src/base/timing.cc
    src/base/util.cc
    src/compiler/ast-dumper.cc
    src/compiler/cfg.cc
    src/compiler/codegen/codegen.cc
    src/compiler/codegen/coercions.cc
    src/compiler/codegen/ctors.cc
    src/compiler/codegen/expressions.cc
    src/compiler/codegen/operators.cc
    src/compiler/codegen/statements.cc
    src/compiler/codegen/types.cc
    src/compiler/codegen/unpack.cc
    src/compiler/coercer.cc
    src/compiler/constant-folder.cc
    src/compiler/context.cc
    src/compiler/cxx/elements.cc
    src/compiler/cxx/formatter.cc
    src/compiler/cxx/linker.cc
    src/compiler/cxx/unit.cc
    src/compiler/driver.cc
    src/compiler/init.cc
    src/compiler/jit.cc
    src/compiler/optimizer/optimizer.cc
    src/compiler/optimizer/pass.cc
    src/compiler/optimizer/passes/constant-propagation.cc
    src/compiler/optimizer/passes/dead-code-cfg.cc
    src/compiler/optimizer/passes/dead-code-static.cc
    src/compiler/optimizer/passes/feature-requirements.cc
    src/compiler/optimizer/passes/flatten-blocks.cc
    src/compiler/optimizer/passes/peephole.cc
    src/compiler/optimizer/passes/propagate-function-returns.cc
    src/compiler/optimizer/passes/remove-unused-params.cc
    src/compiler/parser/driver.cc
    src/compiler/plugin.cc
    src/compiler/printer.cc
    src/compiler/resolver.cc
    src/compiler/scope-builder.cc
    src/compiler/type-unifier.cc
    src/compiler/unit.cc
    src/compiler/validator.cc
    src/global.cc
    # # Already included in hilti-rt, which we pull in.
    # # src/3rdparty/utf8proc/utf8proc.c
    # ${SOURCES_TYPE_ERASED}
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
    if (NOT CMAKE_OSX_SYSROOT)
        message(FATAL_ERROR "CMAKE_OSX_SYSROOT not set")
    endif ()

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

add_executable(hilti-toolchain-tests EXCLUDE_FROM_ALL tests/main.cc tests/id-base.cc
                                                      tests/visitor.cc tests/util.cc tests/graph.cc)
hilti_link_executable_in_tree(hilti-toolchain-tests PRIVATE)
target_link_libraries(hilti-toolchain-tests PRIVATE doctest)
target_compile_options(hilti-toolchain-tests PRIVATE "-Wall")
add_test(NAME hilti-toolchain-tests COMMAND ${PROJECT_BINARY_DIR}/bin/hilti-toolchain-tests)
