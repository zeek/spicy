# Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

##### Compiler library.

set(AUTOGEN_H        "${CMAKE_CURRENT_BINARY_DIR}/include/hilti/autogen")
set(AUTOGEN_RT_H     "${CMAKE_CURRENT_BINARY_DIR}/include/hilti/rt/autogen")
set(AUTOGEN_CC       "${CMAKE_CURRENT_BINARY_DIR}/src/autogen")
file(MAKE_DIRECTORY  "${AUTOGEN_H}" "${AUTOGEN_RT_H}" "${AUTOGEN_CC}")
file(MAKE_DIRECTORY  "${CMAKE_CURRENT_BINARY_DIR}/bin" "${CMAKE_CURRENT_BINARY_DIR}/lib")

add_custom_target(version
                  ALL
                  COMMAND ${PROJECT_SOURCE_DIR}/scripts/autogen-version --header ${AUTOGEN_RT_H}/version.h
                  BYPRODUCTS ${AUTOGEN_RT_H}/version.h)

FLEX_TARGET(scanner_hilti src/compiler/parser/scanner.ll ${AUTOGEN_CC}/__scanner.cc
            DEFINES_FILE ${AUTOGEN_CC}/__scanner.h)
BISON_TARGET(parser_hilti src/compiler/parser/parser.yy ${AUTOGEN_CC}/__parser.cc
            DEFINES_FILE ${AUTOGEN_CC}/__parser.h
)

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
autogen_operators(SOURCES_OPERATORS
                  hilti
                  include/hilti/ast/operators
                  ${AUTOGEN_H}/operators.decl
                  ${AUTOGEN_CC}/operators-implementations.cc
)

autogen_dispatchers(SOURCES_TYPE_ERASED ${AUTOGEN_H}/__dispatchers.h
                                        "hilti/ast/all.h"
                                        ${CMAKE_CURRENT_SOURCE_DIR}/include/hilti/ast/nodes.decl
                                        ${AUTOGEN_H}/operators.decl)

set(SOURCES_COMPILER
    src/ast/builder/builder.cc
    src/ast/builder/type.cc
    src/ast/expression.cc
    src/ast/expressions
    src/ast/expressions/id.cc
    src/ast/location.cc
    src/ast/module.cc
    src/ast/node.cc
    src/ast/node_ref.cc
    src/ast/scope.cc
    src/ast/scope-lookup.cc
    src/ast/type.cc
    src/ast/types/enum.cc
    src/ast/types/integer.cc
    src/ast/types/tuple.cc
    src/base/code-formatter.cc
    src/base/logger.cc
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
    src/compiler/jit.cc
    src/compiler/parser/driver.cc
    src/compiler/plugin.cc
    src/compiler/unit.cc
    src/compiler/visitors/coercer.cc
    src/compiler/visitors/apply-coercions.cc
    src/compiler/visitors/coercer.cc
    src/compiler/visitors/importer.cc
    src/compiler/visitors/printer.cc
    src/compiler/visitors/renderer.cc
    src/compiler/visitors/id-resolver.cc
    src/compiler/visitors/operator-resolver.cc
    src/compiler/visitors/scope-builder.cc
    src/compiler/visitors/validator.cc
    src/global.cc

    $<$<BOOL:${HILTI_HAVE_JIT}>:src/compiler/clang.cc>

    # Already included in hilti-rt, which we pull in.
    # src/3rdparty/utf8proc/utf8proc.c
    src/3rdparty/pathfind/src/PathFind.cpp

    ${SOURCES_TYPE_ERASED}
    ${SOURCES_OPERATORS}

    ${AUTOGEN_CC}/config.cc
    ${BISON_parser_hilti_OUTPUTS}
    ${FLEX_scanner_hilti_OUTPUTS}
    )

# Getting a link error without this.
# (lib64/libhilti.so: undefined reference to `llvm::cfg::Update<llvm::BasicBlock*>::dump() const')
set_source_files_properties(src/compiler/clang.cc PROPERTIES COMPILE_DEFINITIONS "NDEBUG")

add_library(hilti-objects OBJECT ${SOURCES_COMPILER})
set_property(TARGET hilti-objects PROPERTY POSITION_INDEPENDENT_CODE ON)
add_dependencies(hilti-objects version)
target_compile_options(hilti-objects PRIVATE "-Wall")
target_compile_options(hilti-objects PRIVATE $<$<CONFIG:Debug>:-O0>)
target_link_libraries(hilti-objects PUBLIC $<$<BOOL:${HILTI_HAVE_JIT}>:clang-jit>)
target_link_libraries(hilti-objects PUBLIC $<IF:$<CONFIG:Debug>,hilti-rt-debug-objects,hilti-rt-objects>)
target_link_libraries(hilti-objects PUBLIC std::filesystem ${CMAKE_DL_LIBS})
target_link_options(hilti-objects PRIVATE $<$<CONFIG:Debug>:-O0>)
target_include_directories(hilti-objects BEFORE PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
target_include_directories(hilti-objects BEFORE PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>)

# Unclear why we need this: Without it, the generated Bison/Flex get a broken
# include path on some systems. (Seen on Ubuntu 19.10).
set_target_properties(hilti-objects PROPERTIES NO_SYSTEM_FROM_IMPORTED true)

add_library(hilti)
target_link_libraries(hilti PUBLIC hilti-objects)
target_link_libraries(hilti PUBLIC $<IF:$<CONFIG:Debug>,hilti-rt-debug-objects,hilti-rt-objects>) # doesn't transfer from hilti-objects

##### Runtime library.

set(SOURCES_RUNTIME
    src/rt/backtrace.cc
    src/rt/configuration.cc
    src/rt/context.cc
    src/rt/debug-logger.cc
    src/rt/exception.cc
    src/rt/fiber.cc
    src/rt/global-state.cc
    src/rt/init.cc
    src/rt/library.cc
    src/rt/logging.cc
    src/rt/main.cc
    src/rt/type-info.cc
    src/rt/types/address.cc
    src/rt/types/bytes.cc
    src/rt/types/integer.cc
    src/rt/types/port.cc
    src/rt/types/real.cc
    src/rt/types/regexp.cc
    src/rt/types/stream.cc
    src/rt/types/string.cc
    src/rt/types/time.cc
    src/rt/util.cc

    src/3rdparty/libtask/asm.S
    src/3rdparty/libtask/context.c
    src/3rdparty/utf8proc/utf8proc.c
)

foreach ( lib hilti-rt hilti-rt-debug )
    add_library(${lib}-objects OBJECT ${SOURCES_RUNTIME})
    add_dependencies(${lib}-objects version)
    target_compile_options(${lib}-objects PRIVATE "-fPIC")
    target_link_libraries(${lib}-objects PRIVATE std::filesystem ${CMAKE_DL_LIBS})
    target_include_directories(${lib}-objects BEFORE PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
    target_include_directories(${lib}-objects BEFORE PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>)
    target_include_directories(${lib}-objects BEFORE PRIVATE include/3rdparty/libtask)

    # The following should instead just be:
    #
    #    target_link_libraries(${lib}-objects PRIVATE jrx-objects)
    #
    # but does not pull in the object files for some reason. Since at least
    # with cmake-3.16.5 depending on some `TARGET_OBJECTS` does not ensure the
    # referenced target is built before the dependent target is linked, we also
    # explicitly depend on jrx-objects to make sure all its objects are build.
    add_dependencies(${lib}-objects jrx-objects)
    target_include_directories(${lib}-objects BEFORE PRIVATE ${CMAKE_SOURCE_DIR}/3rdparty/justrx/include)
    target_link_libraries(${lib}-objects      PRIVATE $<TARGET_OBJECTS:jrx-objects>)

    add_library(${lib} STATIC)
    target_link_libraries(${lib} ${lib}-objects)

    # Since only an OBJECT libraries usage requirements are propagated
    # transitively, but not its object files, explicitly link against
    # jrx-objects which is an OBJECT library itself and depended on by
    # `jrx-objects`.
    target_link_libraries(${lib} jrx-objects)
endforeach ()

# Build hilti-rt with release flags.
string(REPLACE " " ";" cxx_flags_release ${CMAKE_CXX_FLAGS_RELEASE})
target_compile_options(hilti-rt-objects     PRIVATE ${cxx_flags_release})
target_compile_options(hilti-rt-objects     PRIVATE "-DNDEBUG;-O3;-g0;-Wall")
target_compile_definitions(hilti-rt-objects PRIVATE "HILTI_RT_BUILD_TYPE_RELEASE")

# Build hilti-rt-debug with debug flags.
string(REPLACE " " ";" cxx_flags_debug ${CMAKE_CXX_FLAGS_DEBUG})
target_compile_options(hilti-rt-debug-objects     PRIVATE ${cxx_flags_debug})
target_compile_options(hilti-rt-debug-objects     PRIVATE "-UNDEBUG;-O0;-Wall")
target_compile_definitions(hilti-rt-debug-objects PRIVATE "HILTI_RT_BUILD_TYPE_DEBUG")

##### Configuration files

# HILTI library directories
set_config_val(HILTI_CONFIG_LIBRARY_DIRS "!INSTALL!${CMAKE_INSTALL_FULL_DATADIR}/hilti !BUILD!${CMAKE_CURRENT_SOURCE_DIR}/lib")

# Include directories

set_config_val(HILTI_CONFIG_RUNTIME_INCLUDE_DIRS_DEBUG   "!INSTALL!${CMAKE_INSTALL_FULL_INCLUDEDIR} !BUILD!${CMAKE_CURRENT_SOURCE_DIR}/include !BUILD!${CMAKE_CURRENT_BINARY_DIR}/include")
set_config_val(HILTI_CONFIG_RUNTIME_INCLUDE_DIRS_RELEASE "!INSTALL!${CMAKE_INSTALL_FULL_INCLUDEDIR} !BUILD!${CMAKE_CURRENT_SOURCE_DIR}/include !BUILD!${CMAKE_CURRENT_BINARY_DIR}/include")

# CXX flags

if ( APPLE )
    set(addl_cxx_flags "${cxx_flags} -isysroot ${CMAKE_OSX_SYSROOT}")
endif ()

set_config_val(HILTI_CONFIG_RUNTIME_CXX_FLAGS_DEBUG   "-std=c++17 -g ${addl_cxx_flags} ${EXTRA_CXX_FLAGS} ${CMAKE_CXX_FLAGS}")
set_config_val(HILTI_CONFIG_RUNTIME_CXX_FLAGS_RELEASE "-std=c++17 -O3 -DNDEBUG ${addl_cxx_flags} ${EXTRA_CXX_FLAGS} ${CMAKE_CXX_FLAGS}")

# Libraries

get_target_property(filesystem_library std::filesystem INTERFACE_LINK_LIBRARIES)
if ( NOT filesystem_library )
    set(filesystem_library "")
endif ()

string(REPLACE "-l" "" fslib "${filesystem_library}")
set_config_val(HILTI_CONFIG_RUNTIME_LIBRARIES_DEBUG      "hilti-rt-debug ${fslib}")
set_config_val(HILTI_CONFIG_RUNTIME_LIBRARIES_RELEASE    "hilti-rt ${fslib}")

# Library directories

set_config_val(HILTI_CONFIG_RUNTIME_LIBRARY_DIRS_DEBUG   "!BUILD!${CMAKE_LIBRARY_OUTPUT_DIRECTORY} !INSTALL!${CMAKE_INSTALL_FULL_LIBDIR}")
set_config_val(HILTI_CONFIG_RUNTIME_LIBRARY_DIRS_RELEASE "!BUILD!${CMAKE_LIBRARY_OUTPUT_DIRECTORY} !INSTALL!${CMAKE_INSTALL_FULL_LIBDIR}")

# LD flags

set_config_val(HILTI_CONFIG_RUNTIME_LD_FLAGS_DEBUG   "${EXTRA_LD_FLAGS} ${CMAKE_EXE_LINKER_FLAGS_INIT}")
set_config_val(HILTI_CONFIG_RUNTIME_LD_FLAGS_RELEASE "${EXTRA_LD_FLAGS} ${CMAKE_EXE_LINKER_FLAGS_INIT}")

# Generate configurations

configure_file(include/config.h.in ${AUTOGEN_H}/config.h)
configure_file(include/rt/config.h.in ${AUTOGEN_RT_H}/config.h)
configure_file(src/config.cc.in ${AUTOGEN_CC}/config.cc)

##### Binaries

add_executable(hiltic bin/hiltic.cc)
target_compile_options(hiltic PRIVATE "-Wall")
target_link_hilti(hiltic PRIVATE)

add_executable(hilti-config bin/hilti-config.cc)
target_compile_options(hilti-config PRIVATE "-Wall")
target_link_hilti(hilti-config PRIVATE)

add_executable(jit-test bin/jit-test.cc)
target_compile_options(jit-test PRIVATE "-Wall")
target_link_hilti(jit-test PRIVATE)

# Tests
add_executable(hilti-rt-tests
               src/rt/tests/main.cc
               src/rt/tests/address.cc
               src/rt/tests/bytes.cc
               src/rt/tests/fiber.cc
               src/rt/tests/integer.cc
               src/rt/tests/interval.cc
               src/rt/tests/type-info.cc
               src/rt/tests/map.cc
               src/rt/tests/network.cc
               src/rt/tests/optional.cc
               src/rt/tests/port.cc
               src/rt/tests/real.cc
               src/rt/tests/reference.cc
               src/rt/tests/regexp.cc
               src/rt/tests/result.cc
               src/rt/tests/set.cc
               src/rt/tests/stream.cc
               src/rt/tests/string.cc
               src/rt/tests/to_string.cc
               src/rt/tests/tuple.cc
               src/rt/tests/util.cc
               src/rt/tests/vector.cc)
target_compile_options(hilti-rt-tests PRIVATE "-Wall")
target_link_libraries(hilti-rt-tests PRIVATE hilti-rt-objects doctest)
add_test(NAME hilti-rt-tests COMMAND ${CMAKE_BINARY_DIR}/bin/hilti-rt-tests)

add_executable(hilti-tests
               tests/main.cc
               tests/visitor.cc
               tests/util.cc)
target_link_hilti(hilti-tests PRIVATE)
target_link_libraries(hilti-tests PRIVATE doctest)
target_compile_options(hilti-tests PRIVATE "-Wall")
add_test(NAME hilti-tests COMMAND ${CMAKE_BINARY_DIR}/bin/hilti-tests)

## Installation

install(TARGETS hilti LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(TARGETS hilti-rt hilti-rt-debug ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(TARGETS hiltic hilti-config RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/lib/ DESTINATION ${CMAKE_INSTALL_DATADIR}/hilti MESSAGE_NEVER)

install_headers(include hilti)
install_headers(${CMAKE_CURRENT_BINARY_DIR}/include/hilti hilti)
install(CODE "file(REMOVE ${CMAKE_INSTALL_FULL_INCLUDEDIR}/hilti/hilti)") # Get rid of symlink
