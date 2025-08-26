# Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

cmake_minimum_required(VERSION 3.15.0)

if (APPLE AND CMAKE_VERSION VERSION_GREATER_EQUAL 4.0.0 AND NOT CMAKE_OSX_SYSROOT)
    # We are going to need having CMAKE_OSX_SYSROOT point to the macOS SDK
    # path. However, starting with CMake 4.0, CMAKE_OSX_SYSROOT is not set
    # automatically anymore. So we follow the guidance from the CMake 4.0
    # release notes here:
    #
    #    Builds targeting macOS no longer choose any SDK or pass an "-isysroot"
    #    flag to the compiler by default. Instead, compilers are expected to
    #    choose a default macOS SDK on their own. In order to use a compiler
    #    that does not do this, users must now specify
    #    "-DCMAKE_OSX_SYSROOT=macosx" when configuring their build.
    #
    # The described situation ("let the compiler choose") doesn't quite match
    # ours, but this does lead to CMAKE_OSX_SYSROOT pointing to the macOS SDK
    # path when we need it.
    set(CMAKE_OSX_SYSROOT "macosx")
endif ()

project(spicy LANGUAGES C CXX)

set(flex_minimum_version "2.5.37")
set(bison_minimum_version "3.0")
set(macos_minimum_version "19.0.0") # macOS 10.15.0 (Catalina)

## Initialize defaults & global options

if (NOT CMAKE_BUILD_TYPE)
    # CMake doesn't set build type by default.
    set(CMAKE_BUILD_TYPE "Debug")
endif ()

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)

include(Util)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# CMake uses -O2 by default with RelWithDebInfo.
string(REPLACE "-O2" "-O3" CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO}")

include(CheckCompiler)

include(GNUInstallDirs)
if (NOT CMAKE_RUNTIME_OUTPUT_DIRECTORY)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_INSTALL_BINDIR})
endif ()

if (NOT CMAKE_LIBRARY_OUTPUT_DIRECTORY)
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR})
endif ()

if (NOT CMAKE_ARCHIVE_OUTPUT_DIRECTORY)
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR})
endif ()

if (BINARY_PACKAGING_MODE)
    # Binary packaging mode uses a static link which causes issues with
    # unresolved symbols for a number of tests.
    if (USE_SANITIZERS)
        message(FATAL_ERROR "Sanitizers are unsupported in binary packaging mode")
    endif ()

    set(BUILD_SHARED_LIBS OFF)
    set(CMAKE_SKIP_RPATH ON)
    set(CMAKE_INSTALL_RPATH_USE_LINK_PATH OFF)
    set(CMAKE_MACOSX_RPATH OFF)
else ()
    make_install_rpath(rpath ${CMAKE_INSTALL_FULL_BINDIR} ${CMAKE_INSTALL_FULL_LIBDIR})
    set(CMAKE_INSTALL_RPATH "${rpath}")
endif ()

if (USE_CCACHE)
    find_program(CCACHE_PROGRAM ccache)
    if (CCACHE_PROGRAM)
        set(CMAKE_C_COMPILER_LAUNCHER ${CCACHE_PROGRAM})
        set(CMAKE_CXX_COMPILER_LAUNCHER ${CCACHE_PROGRAM})
    else ()
        set(USE_CCACHE "no (error: could not find ccache)")
    endif ()
else ()
    set(USE_CCACHE "no")
endif ()

if (USE_SANITIZERS)
    # Recommended flags per https://github.com/google/sanitizers/wiki/AddressSanitizer
    set(sanitizer_cxx_flags
        "-fsanitize=${USE_SANITIZERS} -fno-omit-frame-pointer -fno-optimize-sibling-calls -O1")
    set(sanitizer_ld_flags "-fsanitize=${USE_SANITIZERS}")

    if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        set(sanitizer_cxx_flags "${sanitizer_cxx_flags} -shared-libasan")
        set(sanitizer_ld_flags "${sanitizer_ld_flags} -frtlib-add-rpath -shared-libasan")
    endif ()

    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${sanitizer_cxx_flags}")
    set(EXTRA_CXX_FLAGS "${EXTRA_CXX_FLAGS} ${sanitizer_cxx_flags}")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${sanitizer_ld_flags}")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${sanitizer_ld_flags}")
    set(EXTRA_LD_FLAGS "${EXTRA_LD_FLAGS} ${sanitizer_ld_flags}")

    set(HILTI_DEV_PRECOMPILE_HEADERS "no")
endif ()

if (USE_WERROR)
    set(werror_flags "-Werror")

    if (CMAKE_COMPILER_IS_GNUCXX)
        # GCC's `-Wstringop-overflow` has a hardcoded limit for the maximum size
        # of a strings it can analyze which we exceed in e.g., in some
        # benchmarks in some libstd++ use of `__builtin_memcpy`. Disable the
        # warning since it appears noise.
        string(APPEND werror_flags " -Wno-stringop-overflow")

        # With versions >=13.0 GCC gained `-Warray-bounds` which reports false
        # positives, see e.g., https://gcc.gnu.org/bugzilla/show_bug.cgi?id=111273.
        if (CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 13.0)
            string(APPEND werror_flags " -Wno-array-bounds")
        endif ()

        # GCC regularly diagnoses out of bounds access in its own use of
        # `__builtin_memcpy` in e.g., its `bits/char_traits.h`.
        string(APPEND werror_flags " -Wno-restrict")

        # When optimizing GCC often reports false positives around maybe
        # uninitialized values, e.g., in its string implementation. These are
        # extremely tedious to silence, so just disable the warning altogether.
        string(APPEND werror_flags " -Wno-maybe-uninitialized")
    endif ()

    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${werror_flags}")
    set(EXTRA_CXX_FLAGS "${EXTRA_CXX_FLAGS} ${werror_flags}")
endif ()

## Load modules

# If the user specified dedicated prefixes for Flex or Bison, look in these
# prefixes first. As the upstream modules do not support specifying these we
# inject them here by hand.
#
# The implementation relies on the fact that the `find_*` commands do not search
# again should the output variable already be set successfully. We first search
# for the artifacts with `NO_DEFAULT_PATH` and then later trigger the upstream
# `find_package` logic. With that any user-specified prefix takes precedence
# over what could be found in the default search locations.
if (FLEX_ROOT)
    find_program(
        FLEX_EXECUTABLE
        NAMES flex win_flex
        PATHS ${FLEX_ROOT}
        PATH_SUFFIXES bin
        NO_DEFAULT_PATH)
    find_library(
        FL_LIBRARY
        NAMES fl
        PATHS ${FLEX_ROOT}
        PATH_SUFFIXES lib
        NO_DEFAULT_PATH)
    find_path(
        FLEX_INCLUDE_DIR FlexLexer.h
        PATHS ${FLEX_ROOT}
        PATH_SUFFIXES include
        NO_DEFAULT_PATH)
endif ()

if (BISON_ROOT)
    find_program(
        BISON_EXECUTABLE
        NAMES bison win_bison
        PATHS ${BISON_ROOT}
        PATH_SUFFIXES bin
        NO_DEFAULT_PATH)
endif ()

find_package(FLEX REQUIRED)
find_package(BISON REQUIRED)
find_package(ZLIB REQUIRED)
find_package(Backtrace)

if (Backtrace_FOUND AND NOT APPLE)
    # On systems other than MacOS there's a libexecinfo that's not working for us:
    # it seems to break when compiling without frame pointers so we disable it.
    if ("${Backtrace_LIBRARY}" MATCHES "libexecinfo")
        message(STATUS "Disabling backtrace because we found libexecinfo")
        set(Backtrace_FOUND "no")
    endif ()
endif ()

# Prettify output
if (Backtrace_FOUND)
    set(HILTI_HAVE_BACKTRACE "yes")
else ()
    set(HILTI_HAVE_BACKTRACE "no")
endif ()

if (APPLE)
    set(MACOS_FOUND "yes")
    require_version("macOS" MACOS_FOUND ${CMAKE_SYSTEM_VERSION} "${macos_minimum_version}" true)
endif ()

require_version("Flex" FLEX_FOUND FLEX_VERSION "${flex_minimum_version}" true)
require_version("Bison" BISON_FOUND BISON_VERSION "${bison_minimum_version}" true)

find_package(GoldLinker)
find_package(Threads)

option(BUILD_TOOLCHAIN "Build the Spicy compiler toolchain" ON)

if (BUILD_TOOLCHAIN)
    set(HAVE_TOOLCHAIN yes)
else ()
    set(HAVE_TOOLCHAIN no)
endif ()

set(HILTI_COMPILER_LAUNCHER "" CACHE STRING "C++ compiler launcher to use by default during JIT")

# Set up testing infrastructure.
enable_testing()

# Get project version.
file(STRINGS ${CMAKE_CURRENT_SOURCE_DIR}/VERSION SPICY_VERSION LIMIT_COUNT 1)
set(CMAKE_PROJECT_VERSION ${SPICY_VERSION})

# Get Spicy commit. If we cannot get the current commit (e.g., no .git
# directory present for release tarballs), this will leave SPICY_COMMIT unset.
execute_process(
    COMMAND ${CMAKE_COMMAND} -E env GIT_DIR=${CMAKE_CURRENT_SOURCE_DIR}/.git git rev-parse --short
            HEAD
    OUTPUT_VARIABLE SPICY_COMMIT
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_VARIABLE ignored)

string(REGEX MATCH "([0-9]*)\.([0-9]*)\.([0-9]*).*" _ ${CMAKE_PROJECT_VERSION})
math(EXPR SPICY_VERSION_NUMBER
     "${CMAKE_MATCH_1} * 10000 + ${CMAKE_MATCH_2} * 100 + ${CMAKE_MATCH_3}")

if (NOT "${SPICY_COMMIT}" STREQUAL "")
    set(SPICY_VERSION_LONG "${SPICY_VERSION} (${SPICY_COMMIT})")
else ()
    set(SPICY_VERSION_LONG ${SPICY_VERSION})
endif ()

# Add subdirectories.
add_subdirectory(hilti)
add_subdirectory(spicy)
add_subdirectory(scripts)
add_subdirectory(3rdparty)

## Print build summary
string(TOUPPER ${CMAKE_BUILD_TYPE} BuildType)

string(STRIP "${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_${BuildType}}" cflags)
string(STRIP "${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_${BuildType}}" cxxflags)

# Precompiled headers.

option("HILTI_DEV_PRECOMPILE_HEADERS" "Precompile headers for developer tests" ON)

if (${HILTI_DEV_PRECOMPILE_HEADERS} AND TARGET hilti-config AND TARGET spicy-config)
    # Precompile libhilti for use in JIT during development.
    #
    # We only use precompiled headers during JIT, but e.g., not to during
    # compilation of Spicy itself. This gives us the benefits of JIT without
    # e.g., making it harder for ccache to work during development. It also
    # allows us to punt on some trickier cleanups of header files.
    add_custom_command(
        OUTPUT ${PROJECT_BINARY_DIR}/cache/spicy/precompiled_libhilti.h
               ${PROJECT_BINARY_DIR}/cache/spicy/precompiled_libhilti.h.gch
               ${PROJECT_BINARY_DIR}/cache/spicy/precompiled_libhilti_debug.h
               ${PROJECT_BINARY_DIR}/cache/spicy/precompiled_libhilti_debug.h.gch
               ${PROJECT_BINARY_DIR}/cache/spicy/precompiled_libspicy.h
               ${PROJECT_BINARY_DIR}/cache/spicy/precompiled_libspicy.h.gch
               ${PROJECT_BINARY_DIR}/cache/spicy/precompiled_libspicy_debug.h
               ${PROJECT_BINARY_DIR}/cache/spicy/precompiled_libspicy_debug.h.gch
        COMMENT "Generating precompiled headers"
        COMMAND ${CMAKE_COMMAND} -E env SPICY_CACHE=${PROJECT_BINARY_DIR}/cache/spicy
                ${PROJECT_SOURCE_DIR}/scripts/precompile-headers.sh --bindir ${CMAKE_BINARY_DIR}/bin
        DEPENDS ${PROJECT_SOURCE_DIR}/scripts/precompile-headers.sh
                ${CMAKE_CURRENT_SOURCE_DIR}/hilti/runtime/include/libhilti.h
                ${CMAKE_CURRENT_SOURCE_DIR}/spicy/runtime/include/libspicy.h
                hilti-config
                spicy-config)
    add_custom_target(precompiled-headers ALL COMMENT "Generating precompiled headers"
                      DEPENDS ${PROJECT_BINARY_DIR}/cache/spicy/precompiled_libhilti.h)
endif ()

# Global test target
add_custom_target(
    check
    COMMAND ctest --output-on-failure -C $<CONFIG>
    DEPENDS tests
    COMMENT "Running unit tests")
add_custom_target(tests COMMENT "Building test targets")
add_dependencies(tests hilti-tests spicy-tests)

# By default Test targets are built since we want them to be build as part
# of the default dev experience. Projects using Spicy can still disable them
# when bundling Spicy by setting the the option.
option(SPICY_ENABLE_TESTS "Build Spicy unit tests and benchmarks" ON)
if (SPICY_ENABLE_TESTS)
    add_custom_target(tests-build ALL DEPENDS tests COMMENT "Forcing test build")
endif ()

# Packaging.
# Check tags the HEAD commit corresponds to. If we cannot get the current
# commit (e.g., no .git directory present for release tarballs), this will
# leave SPICY_TAGS unset which is fine for users working from tarballs.
execute_process(COMMAND git tag --points-at HEAD v* OUTPUT_VARIABLE SPICY_TAGS
                ERROR_VARIABLE ignored)

if ("${SPICY_TAGS}" STREQUAL "")
    # If the HEAD commit does not correspond to a tag it is not a release. Hide
    # the version number in packaging artifacts so we can e.g., provide stable
    # links to the latest version.
    set(CPACK_PACKAGE_FILE_NAME "${CMAKE_PROJECT_NAME}-dev")
else ()
    # If the HEAD commit corresponds to a tag it is a release and we expect a
    # version number in packaging artifacts.
    set(CPACK_PACKAGE_FILE_NAME "${CMAKE_PROJECT_NAME}-${CMAKE_PROJECT_VERSION}")
endif ()

set(CPACK_PACKAGE_CONTACT "info@zeek.org")

set(CPACK_STRIP_FILES ON)
set(CPACK_SOURCE_STRIP_FILES ON)

set(CPACK_BINARY_DEB OFF)
set(CPACK_BINARY_RPM OFF)
set(CPACK_BINARY_STGZ OFF)
set(CPACK_BINARY_TZ OFF)
set(CPACK_BINARY_TGZ ON)

find_program(RPMBUILD rpmbuild)
if (RPMBUILD)
    set(CPACK_BINARY_RPM ON)
endif ()

find_program(DPKG_DEB dpkg-deb)
if (DPKG_DEB)
    set(CPACK_BINARY_DEB ON)
endif ()

# While this should be sufficient to set a prefix for installation, we still
# bake in other absolute paths by using `CMAKE_INSTALL_FULL_*`-style variables,
# e.g., when baking details about the installation into binaries.
set(CPACK_SET_DESTDIR ON)
set(CPACK_INSTALL_PREFIX "/opt/spicy")
set(CPACK_PACKAGE_RELOCATABLE OFF)

include(CPack)

# Emit configuration summary.

set(SPICY_HOST_SYSTEM "${CMAKE_SYSTEM_NAME} ${CMAKE_SYSTEM_VERSION} (${CMAKE_SYSTEM_PROCESSOR})")
set(SPICY_C_COMPILER "${CMAKE_C_COMPILER} (${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION})")
set(SPICY_CXX_COMPILER
    "${CMAKE_CXX_COMPILER} (${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION})")

set(SPICY_CLANG_TIDY "no")
if (CMAKE_CXX_CLANG_TIDY)
    set(SPICY_CLANG_TIDY "yes (${CMAKE_CXX_CLANG_TIDY})")
endif ()

set(SPICY_SANITIZERS "no")
if (USE_SANITIZERS)
    set(SPICY_SANITIZERS "yes (${USE_SANITIZERS})")
endif ()

message(
    "\n====================|  Spicy Build Summary  |===================="
    "\n"
    "\nVersion:               ${SPICY_VERSION_LONG}"
    "\n"
    "\nBuild type:            ${CMAKE_BUILD_TYPE}"
    "\nBuild directory:       ${PROJECT_BINARY_DIR}"
    "\nInstall prefix:        ${CMAKE_INSTALL_PREFIX}"
    "\nBuild shared libs:     ${BUILD_SHARED_LIBS}"
    "\n"
    "\nHost system:           ${SPICY_HOST_SYSTEM}"
    "\nC compiler:            ${SPICY_C_COMPILER}"
    "\nC++ compiler:          ${SPICY_CXX_COMPILER}"
    "\n"
    "\nBuilding toolchain:    ${HAVE_TOOLCHAIN}"
    "\n"
    "\nUse ccache:            ${USE_CCACHE}"
    "\nUse clang-tidy:        ${SPICY_CLANG_TIDY}"
    "\nUse gold linker:       ${GOLD_FOUND}"
    "\nUse sanitizers:        ${SPICY_SANITIZERS}"
    "\nUse backtrace:         ${HILTI_HAVE_BACKTRACE}"
    "\n"
    "\nWarnings are errors:   ${USE_WERROR}"
    "\nPrecompile headers:    ${HILTI_DEV_PRECOMPILE_HEADERS}"
    "\n"
    "\nBison version:         ${BISON_VERSION}"
    "\nCMake version:         ${CMAKE_VERSION}"
    "\nFlex version:          ${FLEX_VERSION}"
    "\nzlib version:          ${ZLIB_VERSION_STRING}"
    "\n"
    "\n================================================================\n")
