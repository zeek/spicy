# Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

set(AUTOGEN_H        "${CMAKE_BINARY_DIR}/include/hilti/rt/autogen")
set(AUTOGEN_CC       "${CMAKE_BINARY_DIR}/hilti/runtime/src/autogen")
file(MAKE_DIRECTORY  "${AUTOGEN_H}" "${AUTOGEN_CC}")
file(MAKE_DIRECTORY  "${CMAKE_BINARY_DIR}/bin" "${CMAKE_BINARY_DIR}/lib")

##### Runtime libraries

include_directories(${CMAKE_SOURCE_DIR}/3rdparty/libtask/include)

add_custom_target(version
                  ALL
                  COMMAND ${PROJECT_SOURCE_DIR}/scripts/autogen-version --header ${AUTOGEN_H}/version.h --git-root ${CMAKE_CURRENT_SOURCE_DIR}
                  BYPRODUCTS ${AUTOGEN_H}/version.h)

set(SOURCES
    src/backtrace.cc
    src/configuration.cc
    src/context.cc
    src/debug-logger.cc
    src/exception.cc
    src/fiber.cc
    src/global-state.cc
    src/init.cc
    src/library.cc
    src/logging.cc
    src/main.cc
    src/type-info.cc
    src/types/address.cc
    src/types/bytes.cc
    src/types/integer.cc
    src/types/port.cc
    src/types/real.cc
    src/types/regexp.cc
    src/types/stream.cc
    src/types/string.cc
    src/types/time.cc
    src/util.cc

    ${CMAKE_SOURCE_DIR}/3rdparty/libtask/asm.S
    ${CMAKE_SOURCE_DIR}/3rdparty/libtask/context.c
    ${CMAKE_SOURCE_DIR}/3rdparty/utf8proc/utf8proc.c
)

set_source_files_properties(${CMAKE_SOURCE_DIR}/3rdparty/libtask/context.c PROPERTIES COMPILE_OPTIONS "-Wno-null-dereference")

foreach ( lib hilti-rt hilti-rt-debug )
    add_library(${lib}-objects OBJECT ${SOURCES})
    add_dependencies(${lib}-objects version)
    target_compile_options(${lib}-objects PRIVATE "-fPIC")
    target_link_libraries(${lib}-objects PRIVATE std::filesystem Threads::Threads ${CMAKE_DL_LIBS})
    target_include_directories(${lib}-objects BEFORE PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
    target_include_directories(${lib}-objects BEFORE PUBLIC $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>)
    target_include_directories(${lib}-objects BEFORE PUBLIC $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/3rdparty>)

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
target_compile_options(hilti-rt-objects     PRIVATE "-g;-O3;-DNDEBUG;-Wall")
target_compile_definitions(hilti-rt-objects PRIVATE "HILTI_RT_BUILD_TYPE_RELEASE")

# Build hilti-rt-debug with debug flags.
string(REPLACE " " ";" cxx_flags_debug ${CMAKE_CXX_FLAGS_DEBUG})
target_compile_options(hilti-rt-debug-objects     PRIVATE ${cxx_flags_debug})
target_compile_options(hilti-rt-debug-objects     PRIVATE "-UNDEBUG;-O0;-Wall")
target_compile_definitions(hilti-rt-debug-objects PRIVATE "HILTI_RT_BUILD_TYPE_DEBUG")

add_library(hilti-rt-tests-library-dummy1 SHARED src/tests/library-dummy.cc)
target_compile_definitions(hilti-rt-tests-library-dummy1 PUBLIC RETURN_VALUE=1)

add_library(hilti-rt-tests-library-dummy2 SHARED src/tests/library-dummy.cc)
target_compile_definitions(hilti-rt-tests-library-dummy2 PUBLIC RETURN_VALUE=2)

##### Configuration files

configure_file(include/config.h.in ${AUTOGEN_H}/config.h)
configure_file(src/tests/config.h.in ${AUTOGEN_H}/tests/config.h)

##### Binaries

##### Installation

install(TARGETS hilti-rt hilti-rt-debug ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})

install_headers(include hilti/rt)
install_headers(${CMAKE_BINARY_DIR}/include/hilti/rt hilti/rt)
install(CODE "file(REMOVE_RECURSE ${CMAKE_INSTALL_FULL_INCLUDEDIR}/hilti/rt/hilti)") # Get rid of symlink

# Install the 3rdparty headers that we need individually.
install_headers(${CMAKE_SOURCE_DIR}/3rdparty/SafeInt hilti/rt/3rdparty/SafeInt)
install_headers(${CMAKE_SOURCE_DIR}/3rdparty/libtask hilti/rt/3rdparty/libtask)
install_headers(${CMAKE_SOURCE_DIR}/3rdparty/tinyformat hilti/rt/3rdparty/tinyformat)
install_headers(${CMAKE_SOURCE_DIR}/3rdparty/json/single_include/nlohmann hilti/rt/3rdparty/nlohmann)

##### Tests

add_executable(hilti-rt-tests
               src/tests/main.cc
               src/tests/address.cc
               src/tests/backtrace.cc
               src/tests/bytes.cc
               src/tests/context.cc
               src/tests/debug-logger.cc
               src/tests/deferred-expression.cc
               src/tests/exception.cc
               src/tests/fiber.cc
               src/tests/fmt.cc
               src/tests/global-state.cc
               src/tests/hilti.cc
               src/tests/init.cc
               src/tests/integer.cc
               src/tests/interval.cc
               src/tests/iterator.cc
               src/tests/intrusive-ptr.cc
               src/tests/library.cc
               src/tests/logging.cc
               src/tests/map.cc
               src/tests/network.cc
               src/tests/optional.cc
               src/tests/port.cc
               src/tests/real.cc
               src/tests/reference.cc
               src/tests/regexp.cc
               src/tests/result.cc
               src/tests/safe-int.cc
               src/tests/set.cc
               src/tests/stream.cc
               src/tests/string.cc
               src/tests/struct.cc
               src/tests/time.cc
               src/tests/to_string.cc
               src/tests/tuple.cc
               src/tests/type-info.cc
               src/tests/union.cc
               src/tests/util.cc
               src/tests/vector.cc)
target_compile_options(hilti-rt-tests PRIVATE "-Wall")
target_compile_options(hilti-rt-tests PRIVATE $<$<CONFIG:Debug>:-O0>)
target_link_options(hilti-rt-tests PRIVATE $<$<CONFIG:Debug>:-O0>)
target_link_libraries(hilti-rt-tests PRIVATE $<IF:$<CONFIG:Debug>,hilti-rt-debug-objects,hilti-rt-objects> doctest)
add_dependencies(hilti-rt-tests hilti-rt-tests-library-dummy1 hilti-rt-tests-library-dummy2)
add_test(NAME hilti-rt-tests COMMAND ${CMAKE_BINARY_DIR}/bin/hilti-rt-tests)

add_executable(hilti-rt-configuration-tests src/tests/configuration.cc)
target_compile_options(hilti-rt-configuration-tests PRIVATE "-Wall")
target_compile_options(hilti-rt-configuration-tests PRIVATE $<$<CONFIG:Debug>:-O0>)
target_link_options(hilti-rt-configuration-tests PRIVATE $<$<CONFIG:Debug>:-O0>)
target_link_libraries(hilti-rt-configuration-tests PRIVATE $<IF:$<CONFIG:Debug>,hilti-rt-debug-objects,hilti-rt-objects> doctest)
add_test(NAME hilti-rt-configuration-tests COMMAND ${CMAKE_BINARY_DIR}/bin/hilti-rt-configuration-tests)
