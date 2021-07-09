# Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

set(AUTOGEN_H        "${PROJECT_BINARY_DIR}/include/spicy/rt/autogen")
set(AUTOGEN_CC       "${PROJECT_BINARY_DIR}/spicy/runtime/src/autogen")
file(MAKE_DIRECTORY  "${AUTOGEN_H}" "${AUTOGEN_CC}")
file(MAKE_DIRECTORY  "${PROJECT_BINARY_DIR}/bin" "${PROJECT_BINARY_DIR}/lib")

##### Runtime libraries

set(SOURCES
    src/base64.cc
    src/driver.cc
    src/global-state.cc
    src/init.cc
    src/mime.cc
    src/parser.cc
    src/sink.cc
    src/unit-context.cc
    src/util.cc
    src/zlib.cc

    ${PROJECT_SOURCE_DIR}/3rdparty/libb64/src/cdecode.c
    ${PROJECT_SOURCE_DIR}/3rdparty/libb64/src/cencode.c
)

foreach ( lib spicy-rt spicy-rt-debug )
    add_library(${lib}-objects OBJECT ${SOURCES})
    target_compile_options(${lib}-objects PRIVATE "-fPIC")
    target_link_libraries(${lib}-objects PRIVATE ${CMAKE_THREAD_LIBS_INIT} ${CMAKE_DL_LIBS})
    target_link_libraries(${lib}-objects PUBLIC ZLIB::ZLIB)
    target_include_directories(${lib}-objects BEFORE PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
    target_include_directories(${lib}-objects BEFORE PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>)
    target_include_directories(${lib}-objects BEFORE PRIVATE $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/3rdparty/libb64/include>)

    add_library(${lib} STATIC)
    target_link_libraries(${lib} ${lib}-objects)
endforeach ()

# Build spicy-rt with release flags.
string(REPLACE " " ";" cxx_flags_release ${CMAKE_CXX_FLAGS_RELEASE})
target_compile_options(spicy-rt-objects           PRIVATE ${cxx_flags_release})
target_compile_options(spicy-rt-objects           PRIVATE "-g;-O3;-DNDEBUG;-Wall")
target_compile_definitions(spicy-rt-objects       PRIVATE "HILTI_RT_BUILD_TYPE_RELEASE")
target_link_libraries(spicy-rt-objects            PUBLIC hilti-rt-objects)

# Build spicy-rt-debug with debug flags.
string(REPLACE " " ";" cxx_flags_debug ${CMAKE_CXX_FLAGS_DEBUG})
target_compile_options(spicy-rt-debug-objects     PRIVATE ${cxx_flags_debug})
target_compile_options(spicy-rt-debug-objects     PRIVATE "-UNDEBUG;-O0;-Wall")
target_compile_definitions(spicy-rt-debug-objects PRIVATE "HILTI_RT_BUILD_TYPE_DEBUG")
target_link_libraries(spicy-rt-debug-objects      PUBLIC hilti-rt-debug-objects)

##### Configuration files

configure_file(include/config.h.in ${AUTOGEN_H}/config.h)

##### Binaries

##### Installation

install(TARGETS spicy-rt spicy-rt-debug ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})

install_headers(include spicy/rt)
install_headers(${PROJECT_BINARY_DIR}/include/spicy/rt spicy/rt)
install(CODE "file(REMOVE_RECURSE ${CMAKE_INSTALL_FULL_INCLUDEDIR}/spicy/rt/spicy)") # Get rid of symlink

##### Tests

add_executable(spicy-rt-tests
               src/tests/main.cc
               src/tests/base64.cc
               src/tests/debug.cc
               src/tests/global-state.cc
               src/tests/init.cc
               src/tests/mime.cc
               src/tests/parsed-unit.cc
               src/tests/parser.cc
               src/tests/sink.cc
               src/tests/unit-context.cc
               src/tests/util.cc
               src/tests/zlib.cc)

target_compile_options(spicy-rt-tests PRIVATE "-Wall")
target_compile_options(spicy-rt-tests PRIVATE $<$<CONFIG:Debug>:-O0>)
target_link_options(spicy-rt-tests PRIVATE $<$<CONFIG:Debug>:-O0>)
target_link_libraries(spicy-rt-tests PRIVATE $<IF:$<CONFIG:Debug>,hilti-rt-debug,hilti-rt>)
target_link_libraries(spicy-rt-tests PRIVATE $<IF:$<CONFIG:Debug>,spicy-rt-debug,spicy-rt> doctest)
add_test(NAME spicy-rt-tests COMMAND ${PROJECT_BINARY_DIR}/bin/spicy-rt-tests)
